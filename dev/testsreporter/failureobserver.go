// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

type failureObserver interface {
	FirstBuild() string
	UpdateLinks(errorLinks)
	Teams() []string
	SummaryData() map[string]interface{}
	DescriptionData() map[string]interface{}
	String() string
	Labels() []string
}
