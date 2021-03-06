// lint_subject_empty_without_san_test.go
package lints

import (

	"testing"
)

func TestSubEmptyNoSan(t *testing.T) {
	inputPath := "../testlint/testCerts/subjectEmptyNoSan.cer"
	desEnum := Error
	out, _ := Lints["subject_empty_without_san"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestSubEmptyYesSan(t *testing.T) {
	inputPath := "../testlint/testCerts/sanSubjectEmptyNotCritical.cer"
	desEnum := Pass
	out, _ := Lints["subject_empty_without_san"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
