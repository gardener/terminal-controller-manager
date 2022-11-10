/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"fmt"
	"hash/fnv"
	"os"
)

// Set is a map of label:value. It implements Labels.
type Set map[string]string

func ToFnvHash(value string) (string, error) {
	fnvHash := fnv.New64a()

	_, err := fnvHash.Write([]byte(value))
	if err != nil {
		return "", err
	}

	return fmt.Sprint(fnvHash.Sum64()), nil
}

// MergeStringMap combines given maps, and does not check for any conflicts
// between the maps. In case of conflicts, second map (map2) wins
func MergeStringMap(map1 Set, map2 Set) Set {
	var out map[string]string

	if map1 != nil {
		out = make(map[string]string)
	}

	for k, v := range map1 {
		out[k] = v
	}

	if map2 != nil && out == nil {
		out = make(map[string]string)
	}

	for k, v := range map2 {
		out[k] = v
	}

	return out
}

// DataFromSliceOrFile returns data from the slice (if non-empty), or from the file,
// or an error if an error occurred reading the file
func DataFromSliceOrFile(data []byte, file string) ([]byte, error) {
	if len(data) > 0 {
		return data, nil
	}

	if len(file) > 0 {
		fileData, err := os.ReadFile(file)
		if err != nil {
			return []byte{}, err
		}

		return fileData, nil
	}

	return nil, nil
}

// IsAllowed returns true in case the allowList is empty or if the value is included in the list
func IsAllowed(allowList []string, value string) bool {
	if len(allowList) == 0 {
		return true
	}

	for _, allowedValue := range allowList {
		if allowedValue == value {
			return true
		}
	}

	return false
}
