// lint_sub_ca_no_dns_name_contstraints.go
/**************************************************************************************************************************
If the Subordinate CA is not allowed to issue certificates with dNSNames, then the Subordinate CA Certificate
MUST include a zero‐length dNSName in excludedSubtrees. Otherwise, the Subordinate CA Certificate MUST
include at least one dNSName in permittedSubtrees.
**************************************************************************************************************************/

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type subCaBadDnsConstraint struct {
	// Internal data here
}

func (l *subCaBadDnsConstraint) Initialize() error {
	return nil
}

func (l *subCaBadDnsConstraint) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubCA(c) && util.IsExtInCert(c, util.NameConstOID)
}

func (l *subCaBadDnsConstraint) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if len(c.PermittedDNSDomains) == 0 {
		for _, excluded := range c.ExcludedDNSDomains {
			if len(excluded.Data) == 0 {
				return ResultStruct{Result: Pass}, nil
			}
		}
		return ResultStruct{Result: Error}, nil
	} else {
		return ResultStruct{Result: Pass}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "sub_ca_no_dns_name_contstraints",
		Description:   "Subordanate CA certs must include in the name contraints extension either premitted dns names or prohibit the empty DNS name.",
		Providence:    "CAB: 7.1.5",
		EffectiveDate: util.CABV116Date,
		Test:          &subCaBadDnsConstraint{}})
}
