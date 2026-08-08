package passiveauth

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
)

// performs passive-authentication
// SoD is mandatory, CardSecurity is optional
// country will be determined from SoD (certificate) and DG1 will be verified (if present)
// DG hashes will be computed and must match SoD hashes
// returns: passive auth (cert chains) on success for SOD and CardSecurity (where applicable)
func PassiveAuth(doc *document.Document, trustedCerts cms.CertPool) (result *document.PassiveAuthResult, err error) {
	result = &document.PassiveAuthResult{}
	if doc.Mf.Lds1.Sod == nil {
		return result, fmt.Errorf("[PassiveAuth] mandatory file EF.SOD is missing")
	}
	result.DataGroupHashesValid = new(bool)
	if err = validateDgHashes(*doc); err != nil {
		return result, fmt.Errorf("[PassiveAuth] validateDgHashes error: %w", err)
	}
	*result.DataGroupHashesValid = true
	result.SodSignatureValid = new(bool)
	if len(doc.Mf.Lds1.Sod.SD.SignerInfos) < 1 {
		return result, fmt.Errorf("[PassiveAuth] SOD has no SignerInfos")
	}
	config := cms.NewDefaultCMSConfig()
	certificates := make([]cms.Certificate, len(doc.Mf.Lds1.Sod.SD.SignerInfos))
	for i := range doc.Mf.Lds1.Sod.SD.SignerInfos {
		certificate, err := doc.Mf.Lds1.Sod.SD.SignerInfos[i].VerifySignatureWithConfig(config, doc.Mf.Lds1.Sod.SD)
		if err != nil {
			return result, fmt.Errorf("[PassiveAuth] unable to verify SignedData signature (SOD): %w", err)
		}
		certificates[i] = *certificate
	}
	*result.SodSignatureValid = true
	result.CscaChainValid = new(bool)
	countryCscaCertPool, err := countryCscaCerts(doc, trustedCerts)
	if err != nil {
		return result, fmt.Errorf("[PassiveAuth] error getting country CSCA certs: %w", err)
	}
	if countryCscaCertPool.Count() < 1 {
		return result, fmt.Errorf("[PassiveAuth] Cannot perform Passive-Auth as unable to locate any CSCA Certificates for the MRZ Country")
	}
	result.Sod = &document.PassiveAuth{}
	for certificate := range certificates {
		result.Sod.CertChain = append(result.Sod.CertChain, bytes.Clone(certificates[certificate].Raw))
		chain, err := certificates[certificate].VerifyWithConfig(config, countryCscaCertPool)
		if err != nil {
			return result, fmt.Errorf("[PassiveAuth] unable to verify CSCA chain (SOD): %w", err)
		}
		result.Sod.CertChain = append(result.Sod.CertChain, chain...)
	}
	*result.CscaChainValid = true
	slog.Debug("PassiveAuth", "certChain(SOD)-cnt", len(result.Sod.CertChain))
	result.Success = true
	if doc.Mf.CardSecurity != nil {
		result.CardSec = &document.PassiveAuth{}
		result.CardSec.CertChain, err = doc.Mf.CardSecurity.SD.VerifyWithConfig(config, countryCscaCertPool)
		if err != nil {
			result.CardSec = nil
			return result, fmt.Errorf("[PassiveAuth] unable to verify SignedData (CardSecurity): %w", err)
		}

		slog.Debug("PassiveAuth", "certChain(CardSecurity)-cnt", len(result.CardSec.CertChain))
	}
	return result, nil
}

// validates the DG hashes against the hashes in SoD
// will throw error if the document contains a DG that isn't referenced in SoD (e.g. DG injection)
func validateDgHashes(doc document.Document) error {
	// pre-compute the hashes of any applicable DGs in the document
	dgHashes, err := doc.DgHashes()
	if err != nil {
		return fmt.Errorf("[validateDgHashes] DgHashes error : %w", err)
	}

	// for each DG hash from the document, check it matches SoD
	for dgId, dgHash := range dgHashes {
		sodHash := doc.Mf.Lds1.Sod.DgHash(dgId)

		if len(sodHash) <= 0 {
			return fmt.Errorf("[validateDgHashes] DG hash is not present in SoD (dg:%1d) - Data injection!", dgId)
		}

		if !bytes.Equal(dgHash, sodHash) {
			return fmt.Errorf("[validateDgHashes] DG hash mismatch (dg:%1d) (act:%x, exp:%x) - Data tampering!", dgId, dgHash, sodHash)
		}
	}

	return nil
}

// determines the country-code for the document (alpha2)
// primarily uses SoD (Certificate country), but also verifies DG1(MRZ) if DG1 is present
func alpha2CountryCode(doc *document.Document) (alpha2 string, err error) {
	if doc.Mf.Lds1.Sod == nil {
		return "", fmt.Errorf("[Alpha2CountryCode] cannot infer country without SoD")
	}

	sodCountryAlpha2, err := doc.Mf.Lds1.Sod.CertCountryAlpha2()
	if err != nil {
		return "", fmt.Errorf("[Alpha2CountryCode] unable to determine country from SoD: %w", err)
	}

	// verify the DG1 has the same country (if present)
	if doc.Mf.Lds1.Dg1 != nil {
		dg1CountryAlpha2, err := doc.Mf.Lds1.Dg1.IssuingCountryAlpha2()
		if err != nil {
			return "", fmt.Errorf("[Alpha2CountryCode] dg1.GetIssuingCountryAlpha2 error: %w", err)
		}

		if !strings.EqualFold(sodCountryAlpha2, dg1CountryAlpha2) {
			return "", fmt.Errorf("[Alpha2CountryCode] country mismatch between SoD and DG1 (sod:%s, dg1:%s)", sodCountryAlpha2, dg1CountryAlpha2)
		}
	}

	return sodCountryAlpha2, nil
}

// gets the country CSCA certificates based on the document (SOD/DG1)
// NB may return 0 certificates
func countryCscaCerts(doc *document.Document, trustedCerts cms.CertPool) (countryCerts *cms.GenericCertPool, err error) {
	countryCode, err := alpha2CountryCode(doc)
	if err != nil {
		return nil, fmt.Errorf("(countryCscaCerts) unable to get Country-Code from Document: %w", err)
	}

	countryCerts = &cms.GenericCertPool{}
	countryCerts.AddCerts(trustedCerts.ByIssuerCountry(countryCode))

	slog.Debug("countryCscaCerts", "country", countryCode, "cert-cnt", countryCerts.Count())

	return countryCerts, nil
}
