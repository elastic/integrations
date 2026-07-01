// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2"
)

// PostComment posts a result comment on the originating backport PR.
// It is a no-op when backportPRNumber or workingBranch is empty.
func PostComment(backportPRNumber, workingBranch, notFoundPackages, outcome, runID, repository string) error {
	if backportPRNumber == "" || workingBranch == "" {
		return nil
	}

	body, err := buildCommentBody(workingBranch, notFoundPackages, outcome, runID, repository, syncPRURL, branchExistsOnRemote)
	if err != nil {
		return fmt.Errorf("building comment body: %w", err)
	}

	_, _, err = gh.Exec("pr", "comment", backportPRNumber, "--body", body)
	return err
}

func buildCommentBody(
	workingBranch, notFoundPackages, outcome, runID, repository string,
	syncURLFn func(string) (string, error),
	branchExistsFn func(string, string) (bool, error),
) (string, error) {
	switch outcome {
	case "skipped":
		return "**Changelog sync skipped** — all changelog versions are already present on `main`.", nil

	case "success":
		syncURL, err := syncURLFn(workingBranch)
		if err != nil {
			return "", err
		}

		if syncURL != "" {
			body := fmt.Sprintf("**Changelog sync PR created:** %s", syncURL)
			if notFoundPackages != "" {
				body += fmt.Sprintf("\n\n> ⚠️ The following packages were not found on `main` and were skipped: `%s`", notFoundPackages)
			}
			return body, nil
		}

		compareURL := fmt.Sprintf("https://github.com/%s/compare/main...%s", repository, workingBranch)
		body := fmt.Sprintf(
			"**Changelog sync PR created** but its URL could not be retrieved — [open it manually](%s).",
			compareURL,
		)
		if notFoundPackages != "" {
			body += fmt.Sprintf("\n\n> ⚠️ The following packages were not found on `main` and were skipped: `%s`", notFoundPackages)
		}
		return body, nil

	default: // failure
		runURL := fmt.Sprintf("https://github.com/%s/actions/runs/%s", repository, runID)
		body := fmt.Sprintf("**Changelog sync failed.** [View workflow run](%s)", runURL)

		pushed, err := branchExistsFn(workingBranch, repository)
		if err != nil {
			return "", err
		}
		if pushed {
			compareURL := fmt.Sprintf("https://github.com/%s/compare/main...%s", repository, workingBranch)
			body += fmt.Sprintf("\n\nThe working branch was pushed. You can [open a PR manually](%s).", compareURL)
		}
		return body, nil
	}
}

// syncPRURL returns the URL of an open PR with the given head branch, or "".
func syncPRURL(workingBranch string) (string, error) {
	stdout, _, err := gh.Exec("pr", "list",
		"--head", workingBranch,
		"--state", "open",
		"--json", "url",
		"--jq", ".[0].url // empty",
	)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

// branchExistsOnRemote returns true if the branch exists on the remote.
func branchExistsOnRemote(workingBranch, repository string) (bool, error) {
	stdout, _, err := gh.Exec("api",
		fmt.Sprintf("repos/%s/branches/%s", repository, workingBranch),
		"--jq", ".name // empty",
	)
	if err != nil {
		return false, nil // branch not found
	}
	return strings.TrimSpace(stdout.String()) == workingBranch, nil
}
