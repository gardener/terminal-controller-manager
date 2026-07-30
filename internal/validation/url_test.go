/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package validation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation/field"

	internalvalidation "github.com/gardener/terminal-controller-manager/internal/validation"
)

var _ = Describe("ValidateHTTPSURL", func() {
	fldPath := field.NewPath("url")

	It("accepts a valid HTTPS URL", func() {
		Expect(internalvalidation.ValidateHTTPSURL("https://kubernetes.default.svc:443", fldPath)).To(Succeed())
	})

	DescribeTable("rejects an invalid URL",
		func(value, message string) {
			Expect(internalvalidation.ValidateHTTPSURL(value, fldPath)).To(MatchError(ContainSubstring(message)))
		},
		Entry("malformed", "ht!tp://invalid-url", "must be a valid URL"),
		Entry("wrong scheme", "http://kubernetes.default.svc:443", "URL scheme must be https"),
		Entry("missing host", "https://", "URL must have a host"),
	)
})
