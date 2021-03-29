// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

type changelog struct {
	Entries []entry
}

type entry struct {
	Version string
	Changes []change
}

type change struct {
	Description string
	Type        string
	Link        string `yaml:",omitempty"`
}

func newChangelog(initVersion string) *changelog {
	return &changelog{
		[]entry{
			{
				initVersion,
				[]change{
					{
						"initial release",
						"enhancement",
						"", // deliberately empty so user has to specify a real link
					},
				},
			},
		},
	}
}
