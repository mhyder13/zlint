// lint_san_iana_pub_suffix_empty.go

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
	"strings"
)

type pubSuffix struct {
	// Internal data here
}

func (l *pubSuffix) Initialize() error {
	return nil
}

func (l *pubSuffix) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.SanOID)
}

func (l *pubSuffix) RunTest(c *x509.Certificate) (ResultStruct, error) {
	for _, dns := range c.DNSNames {
		if len(strings.Split(dns, ".")) < 3 {
			return ResultStruct{Result: Warn}, nil
		}
	}
	return ResultStruct{Result: Pass}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "san_iana_pub_suffix_empty",
		Description:   "Domain SHOULD NOT have bare public suffix",
		Providence:    "",
		EffectiveDate: util.ZeroDate,
		Test:          &pubSuffix{}})
}
