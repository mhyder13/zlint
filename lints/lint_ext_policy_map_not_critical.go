// lint_ext_policy_map_not_critical.go
/**********************************************************
RFC 5280: 4.2.1.5.  Policy Mappings
This extension MAY be supported by CAs and/or applications.
   Conforming CAs SHOULD mark this extension as critical.
**********************************************************/

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type policyMapCritical struct {
	// Internal data here
}

func (l *policyMapCritical) Initialize() error {
	return nil
}

func (l *policyMapCritical) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.PolicyMapOID)
}

func (l *policyMapCritical) RunTest(c *x509.Certificate) (ResultStruct, error) {
	polMap := util.GetExtFromCert(c, util.PolicyMapOID)
	if polMap.Critical {
		return ResultStruct{Result: Pass}, nil
	} else {
		return ResultStruct{Result: Warn}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "ext_policy_map_not_critical",
		Description:   "Policy mappings should be marked as critical",
		Providence:    "RFC 5280: 4.2.1.5",
		EffectiveDate: util.RFC2459Date,
		Test:          &policyMapCritical{}})
}
