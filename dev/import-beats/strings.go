// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

func uniqueStringValues(fieldNames []string) []string {
	t := make(map[string]bool)
	var unique []string
	for _, f := range fieldNames {
		if _, ok := t[f]; !ok {
			t[f] = true
			unique = append(unique, f)
		}
	}
	return unique
}
