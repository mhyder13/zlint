// lint_ev_locality_name_missing.go

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type evLocalityMissing struct {
	// Internal data here
}

func (l *evLocalityMissing) Initialize() error {
	return nil
}

func (l *evLocalityMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEv(c.PolicyIdentifiers)
}

func (l *evLocalityMissing) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if util.TypeInName(&c.Subject, util.LocalityNameOID) {
		return ResultStruct{Result: Pass}, nil
	} else {
		return ResultStruct{Result: Error}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "ev_locality_name_missing",
		Description:   "EV certificates must include localityName in subject",
		Providence:    "",
		EffectiveDate: util.ZeroDate,
		Test:          &evLocalityMissing{}})
}
