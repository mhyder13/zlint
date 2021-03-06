// lint_ext_san_dns_not_ia5_string_test.go
package lints

import (

	"testing"
)

func TestSanDnsNotIa5(t *testing.T) {
	inputPath := "../testlint/testCerts/sanDnsNotIa5.cer"
	desEnum := Error
	out, _ := Lints["ext_san_dns_not_ia5_string"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestSanDnsIa5(t *testing.T) {
	inputPath := "../testlint/testCerts/sanCaGood.cer"
	desEnum := Pass
	out, _ := Lints["ext_san_dns_not_ia5_string"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
