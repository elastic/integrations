// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

var baseFields = createBaseFields()

func createBaseFields() []fieldDefinition {
	return []fieldDefinition{
		{
			Name:        "stream.type",
			Type:        "constant_keyword",
			Description: "Stream type.",
		},
		{
			Name:        "stream.dataset",
			Type:        "constant_keyword",
			Description: "Stream dataset.",
		},
		{
			Name:        "stream.namespace",
			Type:        "constant_keyword",
			Description: "Stream namespace.",
		},
		{
			Name:        "@timestamp",
			Type:        "date",
			Description: "Event timestamp.",
		},
	}
}
