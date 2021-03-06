// lint_ev_organization_name_missing.go

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type evOrgMissing struct {
	// Internal data here
}

func (l *evOrgMissing) Initialize() error {
	return nil
}

func (l *evOrgMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEv(c.PolicyIdentifiers)
}

func (l *evOrgMissing) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if util.TypeInName(&c.Subject, util.OrganizationNameOID) {
		return ResultStruct{Result: Pass}, nil
	} else {
		return ResultStruct{Result: Error}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "ev_organization_name_missing",
		Description:   "EV certificates must include organizationName in subject",
		Providence:    "",
		EffectiveDate: util.ZeroDate,
		Test:          &evOrgMissing{}})
}
