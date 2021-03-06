// lint_sub_ca_certificate_policies_marked_critical.go
/************************************************
CAB: 7.1.2.2a certificatePolicies
This extension MUST be present and SHOULD NOT be marked critical.
************************************************/

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type subCACertPolicyCrit struct {
	// Internal data here
}

func (l *subCACertPolicyCrit) Initialize() error {
	return nil
}

func (l *subCACertPolicyCrit) CheckApplies(c *x509.Certificate) bool {
	// Add conditions for application here
	return util.IsSubCA(c) && util.IsExtInCert(c, util.CertPolicyOID)
}

func (l *subCACertPolicyCrit) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if e := util.GetExtFromCert(c, util.CertPolicyOID); e.Critical {
		return ResultStruct{Result: Warn}, nil
	} else {
		return ResultStruct{Result: Pass}, nil
	}

}

func init() {
	RegisterLint(&Lint{
		Name:          "sub_ca_certificate_policies_marked_critical",
		Description:   "Subordinate CA certificates certificatePolicies extension should not be marked as critical",
		Providence:    "CAB: 7.1.2.2",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCACertPolicyCrit{}})
}
