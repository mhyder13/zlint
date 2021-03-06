// lint_ext_ian_empty_name.go
/******************************************************************
RFC 5280: 4.2.1.7
If the subjectAltName extension is present, the sequence MUST contain
at least one entry.  Unlike the subject field, conforming CAs MUST
NOT issue certificates with subjectAltNames containing empty
GeneralName fields.  For example, an rfc822Name is represented as an
IA5String.  While an empty string is a valid IA5String, such an
rfc822Name is not permitted by this profile.  The behavior of clients
that encounter such a certificate when processing a certification
path is not defined by this profile.
******************************************************************/

package lints

import (
	"encoding/asn1"

	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type ianEmptyName struct {
	// Internal data here
}

func (l *ianEmptyName) Initialize() error {
	return nil
}

func (l *ianEmptyName) CheckApplies(c *x509.Certificate) bool {
	return util.IsExtInCert(c, util.IssuerANOID)
}

func (l *ianEmptyName) RunTest(c *x509.Certificate) (ResultStruct, error) {
	value := util.GetExtFromCert(c, util.IssuerANOID).Value
	var seq asn1.RawValue
	var err error
	if _, err = asn1.Unmarshal(value, &seq); err != nil {
		return ResultStruct{Result: NA}, err
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		err = asn1.StructuralError{Msg: "bad SAN sequence"}
		return ResultStruct{Result: NA}, err
	}

	rest := seq.Bytes
	for len(rest) > 0 {

		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return ResultStruct{Result: NA}, err
		}
		if len(v.Bytes) == 0 {
			return ResultStruct{Result: Error}, nil
		}
	}
	return ResultStruct{Result: Pass}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "ext_ian_empty_name",
		Description:   "general name fields must not be empty in ian",
		Providence:    "RFC 5280: 4.2.1.7",
		EffectiveDate: util.RFC2459Date,
		Test:          &ianEmptyName{}})
}
