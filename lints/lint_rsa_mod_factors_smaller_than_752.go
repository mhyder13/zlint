// lint_rsa_mod_factors_smaller_than_752.go
/**************************************************************************************************
6.1.6. Public Key Parameters Generation and Quality Checking
RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or more. Additionally, the public exponent SHOULD be in the range between 216+1 and 2256-1. The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752. [Source: Section 5.3.3, NIST SP 800‐89].
**************************************************************************************************/

package lints

import (

	"crypto/rsa"
	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
)

type rsaModSmallFactor struct {
	// Internal data here
}

func (l *rsaModSmallFactor) Initialize() error {
	return nil
}

func (l *rsaModSmallFactor) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.RSA
}

func (l *rsaModSmallFactor) RunTest(c *x509.Certificate) (ResultStruct, error) {
	mod := c.PublicKey.(*rsa.PublicKey).N
	if util.PrimeNoSmallerThan752(mod) {
		return ResultStruct{Result: Pass}, nil
	}
	return ResultStruct{Result: Warn}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "rsa_mod_factors_smaller_than_752",
		Description:   "The modulus of a RSA public key should have no factors smaller than 752",
		Providence:    "CAB: 6.1.6",
		EffectiveDate: util.CABV113Date,
		Test:          &rsaModSmallFactor{}})
}
