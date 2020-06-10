/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
	"hash/fnv"
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
