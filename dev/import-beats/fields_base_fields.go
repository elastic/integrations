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
			Description: "Data stream dataset name.",
		},
		{
			Name:        "data_stream.namespace",
			Type:        "constant_keyword",
			Description: "Data stream namespace.",
		},
		// TODO: This should be removed as soon as it is not a requirement anymore by the validation
		// PR to change this can be found here: https://github.com/elastic/package-registry/pull/618
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
