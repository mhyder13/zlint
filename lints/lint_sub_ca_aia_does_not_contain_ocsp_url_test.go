// lint_sub_ca_aia_does_not_contain_ocsp_url_test.go
package lints

import (

	"testing"
)

func TestSubCaAiaNoOcsp(t *testing.T) {
	inputPath := "../testlint/testCerts/subCAWIssuerURL.cer"
	desEnum := Error
	out, _ := Lints["sub_ca_aia_does_not_contain_ocsp_url"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestSubCaAiaHasOcsp(t *testing.T) {
	inputPath := "../testlint/testCerts/subCAWOcspURL.cer"
	desEnum := Pass
	out, _ := Lints["sub_ca_aia_does_not_contain_ocsp_url"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
