// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

var baseFields = createBaseFields()

func createBaseFields() []fieldDefinition {
	return []fieldDefinition{
		{
			Name:        "data_stream.type",
			Type:        "constant_keyword",
			Description: "Data stream type.",
		},
		{
			Name:        "data_stream.dataset",
			Type:        "constant_keyword",
			Description: "Data stream dataset.",
		},
		{
			Name:        "data_stream.namespace",
			Type:        "constant_keyword",
			Description: "Data stream namespace.",
		},
		{
			Name:        "@timestamp",
			Type:        "date",
			Description: "Event timestamp.",
		},
	}
}
