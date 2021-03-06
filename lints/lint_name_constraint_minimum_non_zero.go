// lint_name_constraint_minimum_non_zero.go
/************************************************************************
RFC 5280: 4.2.1.10
Within this profile, the minimum and maximum fields are not used with
any name forms, thus, the minimum MUST be zero, and maximum MUST be
absent.  However, if an application encounters a critical name
constraints extension that specifies other values for minimum or
maximum for a name form that appears in a subsequent certificate, the
application MUST either process these fields or reject the
certificate.
************************************************************************/

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type nameConstMin struct {
	// Internal data here
}

func (l *nameConstMin) Initialize() error {
	return nil
}

func (l *nameConstMin) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.NameConstOID)
}

func (l *nameConstMin) RunTest(c *x509.Certificate) (ResultStruct, error) {
	for _, i := range c.PermittedDNSDomains {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.ExcludedDNSDomains {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.PermittedEmailDomains {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.ExcludedEmailDomains {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.PermittedIPAddresses {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.ExcludedIPAddresses {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.PermittedDirectoryNames {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.ExcludedDirectoryNames {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.PermittedEdiPartyNames {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.ExcludedEdiPartyNames {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.PermittedRegisteredIDs {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.ExcludedRegisteredIDs {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.PermittedX400Addresses {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	for _, i := range c.ExcludedX400Addresses {
		if i.Min != 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	return ResultStruct{Result: Pass}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "name_constraint_minimum_non_zero",
		Description:   "In the name constraints name forms the minimum is not used and therefore MUST be zero",
		Providence:    "RFC 5280: 4.2.1.10",
		EffectiveDate: util.RFC2459Date,
		Test:          &nameConstMin{}})
}
