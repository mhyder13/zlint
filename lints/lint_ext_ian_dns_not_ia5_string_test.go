// lint_ext_ian_dns_not_ia5_string_test.go
package lints

import (

	"testing"
)

func TestIanDnsIa5(t *testing.T) {
	inputPath := "../testlint/testCerts/ianDnsIa5.cer"
	desEnum := Pass
	out, _ := Lints["ext_ian_dns_not_ia5_string"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestIanDnsNotIa5(t *testing.T) {
	inputPath := "../testlint/testCerts/ianDnsNotIa5.cer"
	desEnum := Error
	out, _ := Lints["ext_ian_dns_not_ia5_string"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
