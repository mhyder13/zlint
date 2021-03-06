// lint_ext_san_no_entries_test.go
package lints

import (

	"testing"
)

func TestSanNoEntry(t *testing.T) {
	inputPath := "../testlint/testCerts/sanNoEntries.cer"
	desEnum := Error
	out, _ := Lints["ext_san_no_entries"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestSanHasEntry(t *testing.T) {
	inputPath := "../testlint/testCerts/orgValGoodAllFields.cer"
	desEnum := Pass
	out, _ := Lints["ext_san_no_entries"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
