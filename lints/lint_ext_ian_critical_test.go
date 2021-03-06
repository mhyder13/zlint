// lint_ext_ian_critical_test.go
package lints

import (

	"testing"
)

func TestIanCrit(t *testing.T) {
	inputPath := "../testlint/testCerts/ianCritical.cer"
	desEnum := Warn
	out, _ := Lints["ext_ian_critical"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestIanNotCrit(t *testing.T) {
	inputPath := "../testlint/testCerts/ianNotCritical.cer"
	desEnum := Pass
	out, _ := Lints["ext_ian_critical"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
