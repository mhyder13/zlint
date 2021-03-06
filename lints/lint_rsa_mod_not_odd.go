// lint_rsa_mod_not_odd.go
/*******************************************************************************************************
"CAB: 6.1.6"
RSA: The CA SHALL confirm that the value of the public exponent is an odd number equal to 3 or	more. Additionally,	the public exponent SHOULD be in the range between 2^16+1 and 2^256-1. The modulus SHOULD also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752. [Source: Section 5.3.3, NIST SP 800-89].
*******************************************************************************************************/

package lints

import (

	"crypto/rsa"
	"github.com/zmap/zlint/util"
	"github.com/zmap/zgrab/ztools/x509"
	"math/big"
)

type rsaParsedTestsKeyModOdd struct {
	// Internal data here
}

func (l *rsaParsedTestsKeyModOdd) Initialize() error {
	return nil
}

func (l *rsaParsedTestsKeyModOdd) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.RSA
}

func (l *rsaParsedTestsKeyModOdd) RunTest(c *x509.Certificate) (ResultStruct, error) {
	theKey := c.PublicKey.(*rsa.PublicKey)
	z := big.NewInt(0)
	if (z.Mod(theKey.N, big.NewInt(2)).Cmp(big.NewInt(1))) == 0 {
		return ResultStruct{Result: Pass}, nil
	} else {
		return ResultStruct{Result: Warn}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "rsa_mod_not_odd",
		Description:   "The modulus of a RSA public key should be an odd number",
		Providence:    "CAB: 6.1.6",
		EffectiveDate: util.CABV113Date,
		Test:          &rsaParsedTestsKeyModOdd{}})
}
