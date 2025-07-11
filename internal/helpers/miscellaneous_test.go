/*
SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package helpers_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/terminal-controller-manager/internal/helpers"
)

var _ = Describe("miscellaneous", func() {
	Describe("ToFnvHash", func() {
		Context("When a string is passed", func() {
			It("should return hash without error", func() {
				value := "test string"
				hash, err := helpers.ToFnvHash(value)

				Expect(err).NotTo(HaveOccurred())
				Expect(hash).To(Equal("10983430520173899754"))
			})
		})

		Context("When an empty string is passed", func() {
			It("should return hash without error", func() {
				value := ""
				hash, err := helpers.ToFnvHash(value)

				Expect(err).NotTo(HaveOccurred())
				Expect(hash).To(Equal("14695981039346656037"))
			})
		})
	})
})
