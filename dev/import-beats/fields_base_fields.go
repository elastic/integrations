// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

var baseFields = createBaseFields()

func createBaseFields() []fieldDefinition {
	return []fieldDefinition{
		{
			Name:        "dataset.type",
			Type:        "constant_keyword",
			Description: "Dataset type.",
		},
		{
			Name:        "dataset.name",
			Type:        "constant_keyword",
			Description: "Dataset name.",
		},
		{
			Name:        "dataset.namespace",
			Type:        "constant_keyword",
			Description: "Dataset namespace.",
		},
		{
			Name:        "@timestamp",
			Type:        "date",
			Description: "Event timestamp.",
		},
	}
}
