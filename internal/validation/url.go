/*
SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package validation

import (
	"fmt"
	"net/url"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateHTTPSURL validates that value is a URL with an HTTPS scheme and a host.
func ValidateHTTPSURL(value string, fldPath *field.Path) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return field.Invalid(fldPath, value, fmt.Sprintf("must be a valid URL: %v", err))
	}

	if parsed.Scheme != "https" {
		return field.Invalid(fldPath, value, "URL scheme must be https")
	}

	if parsed.Host == "" {
		return field.Invalid(fldPath, value, "URL must have a host")
	}

	return nil
}
