// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package assign resolves the GitHub login that should be set as assignee on
// automatically-created PRs (backport PRs, changelog-sync PRs). It prefers the
// source PR's author when they are not a bot and have repo write access, and
// falls back to whoever merged the PR otherwise.
package assign

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2"
)

// PRActor holds the login and bot flag for a PR participant.
type PRActor struct {
	Login string `json:"login"`
	IsBot bool   `json:"is_bot"`
}

// Resolve fetches author and mergedBy from the given PR and returns the login
// that should be set as assignee. Returns an empty string on any lookup
// failure so the caller can skip --assignee gracefully.
func Resolve(prNumber, repository string) string {
	if prNumber == "" || repository == "" {
		return ""
	}
	stdout, _, err := gh.Exec("pr", "view", prNumber, "--repo", repository,
		"--json", "author,mergedBy")
	if err != nil {
		return ""
	}
	var data struct {
		Author   PRActor `json:"author"`
		MergedBy PRActor `json:"mergedBy"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &data); err != nil {
		return ""
	}
	hasWriteAccess := func(login string) bool {
		out, _, err := gh.Exec("api",
			fmt.Sprintf("repos/%s/collaborators/%s/permission", repository, login),
			"--jq", ".permission")
		if err != nil {
			return false
		}
		perm := strings.TrimSpace(out.String())
		return perm == "write" || perm == "maintain" || perm == "admin"
	}
	return Pick(data.Author, data.MergedBy, hasWriteAccess)
}

// Pick returns the author login when the author is not a bot and has repo
// write access. Falls back to mergedBy when the author check fails, as long
// as mergedBy is not a bot and still has repo write access. Returns empty
// string if neither qualifies. Both paths check write access so that a login
// that lost access after the PR was merged does not cause gh pr create
// --assignee to fail and abort backport PR creation.
func Pick(author, mergedBy PRActor, hasWriteAccess func(string) bool) string {
	if !author.IsBot && author.Login != "" && hasWriteAccess(author.Login) {
		return author.Login
	}
	if !mergedBy.IsBot && mergedBy.Login != "" && hasWriteAccess(mergedBy.Login) {
		return mergedBy.Login
	}
	return ""
}
