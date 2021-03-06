// lint_ext_subject_key_identifier_critical_test.go
package lints

import (

	"testing"
)

func TestSkiCrit(t *testing.T) {
	inputPath := "../testlint/testCerts/skiCriticalCA.cer"
	desEnum := Error
	out, _ := Lints["ext_subject_key_identifier_critical"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestSkiNotCrit(t *testing.T) {
	inputPath := "../testlint/testCerts/skiNotCriticalCA.cer"
	desEnum := Pass
	out, _ := Lints["ext_subject_key_identifier_critical"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
