// lint_ext_cert_policy_explicit_text_not_nfc.go
/************************************************
  When the UTF8String encoding is used, all character sequences SHOULD be
  normalized according to Unicode normalization form C (NFC) [NFC].
************************************************/

package lints

import (

	"github.com/teamnsrg/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
	"golang.org/x/text/unicode/norm"
)

type ExtCertPolicyExplicitTextNotNFC struct {
	// Internal data here
}

func (l *ExtCertPolicyExplicitTextNotNFC) Initialize() error {
	return nil
}

func (l *ExtCertPolicyExplicitTextNotNFC) CheckApplies(c *x509.Certificate) bool {
	for _, text := range c.ExplicitTexts {
		if text != nil {
			return true
		}
	}
	return false
}

func (l *ExtCertPolicyExplicitTextNotNFC) RunTest(c *x509.Certificate) (ResultStruct, error) {
	for _, firstLvl := range c.ExplicitTexts {
		for _, text := range firstLvl {
			if text.Tag == 12 || text.Tag == 30 {
				if !norm.NFC.IsNormal(text.Bytes) {
					return ResultStruct{Result: Warn}, nil
				}
			}
		}
	}
	return ResultStruct{Result: Pass}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "ext_cert_policy_explicit_text_not_nfc",
		Description:   "When utf8string or bmpstring encoding is used for explicitText field in cert policy, it SHOULD BE normalized by NFC format",
		Providence:    "Fill this in...",
		EffectiveDate: util.RFC6818Date,
		Test:          &ExtCertPolicyExplicitTextNotNFC{}})
}