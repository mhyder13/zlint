// lint_sub_ca_certificate_policies_marked_critical_test.go
package lints

import (

	"testing"
)

func TestSubCaPolicyCrit(t *testing.T) {
	inputPath := "../testlint/testCerts/subCAWCertPolicyCrit.cer"
	desEnum := Warn
	out, _ := Lints["sub_ca_certificate_policies_marked_critical"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestSubCaPolicyNotCrit(t *testing.T) {
	inputPath := "../testlint/testCerts/subCAWCertPolicyNoCrit.cer"
	desEnum := Pass
	out, _ := Lints["sub_ca_certificate_policies_marked_critical"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
