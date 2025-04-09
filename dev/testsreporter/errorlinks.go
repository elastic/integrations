// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

type errorLinks struct {
	currentIssueURL string
	firstBuild      string
	previousBuilds  []string
	closedIssueURL  string
}

func (e *errorLinks) Data() map[string]any {
	return map[string]any{
		"firstBuild":     e.firstBuild,
		"closedIssueURL": e.closedIssueURL,
		"previousBuilds": e.previousBuilds,
	}
}
