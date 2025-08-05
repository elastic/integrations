// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"fmt"
	"strings"
)

type dataError struct {
	errorLinks
	serverless        bool
	serverlessProject string
	logsDB            bool
	stackVersion      string
	subscription      string
}

func (d *dataError) String() string {
	var sb strings.Builder

	if d.logsDB {
		sb.WriteString("[LogsDB] ")
	}
	if d.serverless {
		sb.WriteString(fmt.Sprintf("[Serverless %s] ", d.serverlessProject))
	}
	if d.stackVersion != "" {
		sb.WriteString("[Stack ")
		sb.WriteString(d.stackVersion)
		sb.WriteString("] ")
	}
	if d.subscription != "" {
		sb.WriteString("[Subscription ")
		sb.WriteString(d.subscription)
		sb.WriteString("] ")
	}
	return sb.String()
}

func (d *dataError) Data() map[string]any {
	return map[string]any{
		"stackVersion":      d.stackVersion,
		"serverless":        d.serverless,
		"serverlessProject": d.serverlessProject,
		"logsDB":            d.logsDB,
		"subscription":      d.subscription,
	}
}
