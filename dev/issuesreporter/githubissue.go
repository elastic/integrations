// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package issuesreporter

type GithubIssue struct {
	repository  string
	user        string
	number      int
	title       string
	description string
	labels      []string
}

func (i *GithubIssue) Number() int {
	return i.number
}

type GithubIssueOptions struct {
	Repository  string
	Title       string
	Description string
	User        string
	Labels      []string
}

func NewGithubIssue(options GithubIssueOptions) *GithubIssue {
	issue := GithubIssue{
		title:       options.Title,
		description: options.Description,
		repository:  options.Repository,
		labels:      options.Labels,
		user:        options.User,
	}

	return &issue
}
