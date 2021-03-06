// lint_ext_ian_no_entries_test.go
package lints

import (

	"testing"
)

func TestIanNoEntry(t *testing.T) {
	inputPath := "../testlint/testCerts/ianEmpty.cer"
	desEnum := Error
	out, _ := Lints["ext_ian_no_entries"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestIanHasEntry(t *testing.T) {
	inputPath := "../testlint/testCerts/ianDnsIa5.cer"
	desEnum := Pass
	out, _ := Lints["ext_ian_no_entries"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
