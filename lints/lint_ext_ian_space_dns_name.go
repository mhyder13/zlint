// lint_ext_ian_space_dns_name.go
/**********************************************************************
RFC 5280: 4.2.1.7
When the issuerAltName extension contains a domain name system
label, the domain name MUST be stored in the dNSName (an IA5String).
The name MUST be in the "preferred name syntax", as specified by
Section 3.5 of [RFC1034] and as modified by Section 2.1 of
[RFC1123].  Note that while uppercase and lowercase letters are
allowed in domain names, no significance is attached to the case.  In
addition, while the string " " is a legal domain name, subjectAltName
extensions with a dNSName of " " MUST NOT be used.  Finally, the use
of the DNS representation for Internet mail addresses
(subscriber.example.com instead of subscriber@example.com) MUST NOT
be used; such identities are to be encoded as rfc822Name.  Rules for
encoding internationalized domain names are specified in Section 7.2.
**********************************************************************/

package lints

import (

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type ianSpace struct {
	// Internal data here
}

func (l *ianSpace) Initialize() error {
	return nil
}

func (l *ianSpace) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.IssuerANOID)
}

func (l *ianSpace) RunTest(c *x509.Certificate) (ResultStruct, error) {
	for _, dns := range c.IANDNSNames {
		if dns == " " {
			return ResultStruct{Result: Error}, nil
		}
	}
	return ResultStruct{Result: Pass}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "ext_ian_space_dns_name",
		Description:   "the dNSName ` ` must not be used",
		Providence:    "RFC 5280: 4.2.1.6",
		EffectiveDate: util.RFC2459Date,
		Test:          &ianSpace{}})
}
