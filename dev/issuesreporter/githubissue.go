package issuesreporter

import "os"

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
	Labels      []string
}

func NewGithubIssue(options GithubIssueOptions) *GithubIssue {
	issue := GithubIssue{
		title:       options.Title,
		description: options.Description,
		repository:  options.Repository,
		labels:      options.Labels,
	}

	user := os.Getenv("GITHUB_USERNAME_SECRET")
	issue.user = user
	if user == "" {
		issue.user = "mrodm"
	}

	return &issue
}
