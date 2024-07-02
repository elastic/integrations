// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

type GithubIssue struct {
	repository  string
	number      int
	title       string
	description string
	labels      []string
	state       string
	url         string
}

func (i *GithubIssue) Number() int {
	return i.number
}

func (i *GithubIssue) Open() bool {
	return i.state == "OPEN"
}

func (i *GithubIssue) URL() string {
	return i.url
}

type GithubIssueOptions struct {
	Repository  string
	Title       string
	Description string
	Labels      []string
	Number      int
	State       string
	URL         string
}

func NewGithubIssue(options GithubIssueOptions) *GithubIssue {
	issue := GithubIssue{
		title:       options.Title,
		description: options.Description,
		repository:  options.Repository,
		labels:      options.Labels,
		number:      options.Number,
		state:       options.State,
		url:         options.URL,
	}

	return &issue
}

func (i *GithubIssue) SetDescription(description string) {
	i.description = description
}
