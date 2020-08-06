// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

type searchIssuesResponse struct {
	Items []pullRequest `json:"items"`
}

type createPullRequestResponse struct {
	Number         int           `json:"number"`
	RequestedTeams []interface{} `json:"requested_teams"`
	RequestedUsers []interface{} `json:"requested_users"`
}

type pullRequest struct {
	Title string `json:"title"`
}

func openPullRequest(err error, options updateOptions, packageName, packageVersion, username, branchName, commitHash string) (int, error) {
	if err != nil {
		return 0, err
	}

	if options.skipPullRequest {
		return 0, nil
	}

	authToken, err := getAuthToken()
	if err != nil {
		return 0, errors.Wrap(err, "fetching auth token failed")
	}

	title := buildPullRequestTitle(packageName, packageVersion)
	diffURL := buildPullRequestDiffURL(username, commitHash)
	description := buildPullRequestDescription(packageName, packageVersion, diffURL)

	requestBody, err := buildPullRequestRequestBody(title, username, branchName, description)
	if err != nil {
		return 0, errors.Wrap(err, "building request body failed")
	}

	request, err := http.NewRequest("POST", "https://api.github.com/repos/elastic/package-storage/pulls", bytes.NewReader(requestBody))
	if err != nil {
		return 0, errors.Wrap(err, "creating new HTTP request failed")
	}

	request.Header.Add("Authorization", fmt.Sprintf("token %s", authToken))
	request.Header.Add("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, errors.Wrap(err, "making HTTP call failed")
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return 0, fmt.Errorf("unexpected status code return while opening a pull request: %d", response.StatusCode)
	}

	var data createPullRequestResponse
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return 0, errors.Wrap(err, "can't read response body")
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return 0, errors.Wrap(err, "unmarshalling response failed")
	}
	return data.Number, nil
}

func updatePullRequestReviewers(err error, pullRequestID int, reviewer string) error {
	if err != nil {
		return err
	}

	requested, err := updatePullRequestReviewersWithoutFallback(pullRequestID, reviewer)
	if err != nil {
		return errors.Wrap(err, "updating reviewers failed")
	}

	if requested {
		return nil // success
	}

	// Fallback to default package owner
	requested, err = updatePullRequestReviewersWithoutFallback(pullRequestID, defaultPackageOwner)
	if err != nil {
		return errors.Wrap(err, "updating fallback reviewers failed")
	}

	if !requested {
		return errors.New("can't request review from any package owner")
	}
	return nil
}

func updatePullRequestReviewersWithoutFallback(pullRequestID int, reviewer string) (bool, error) {
	authToken, err := getAuthToken()
	if err != nil {
		return false, errors.Wrap(err, "fetching auth token failed")
	}

	requestBody, err := buildPullRequestReviewersRequestBody(reviewer)
	if err != nil {
		return false, errors.Wrap(err, "building reviewers request body failed")
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("https://api.github.com/repos/elastic/package-storage/pulls/%d/requested_reviewers", pullRequestID),
		bytes.NewReader(requestBody))
	if err != nil {
		return false, errors.Wrap(err, "creating new HTTP request failed")
	}

	request.Header.Add("Authorization", fmt.Sprintf("token %s", authToken))
	request.Header.Add("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, errors.Wrap(err, "making HTTP call failed")
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return false, fmt.Errorf("unexpected status code return while opening a pull request: %d", response.StatusCode)
	}

	var data createPullRequestResponse
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, errors.Wrap(err, "can't read response body")
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return false, errors.Wrap(err, "unmarshalling response failed")
	}

	if len(data.RequestedTeams) == 0 && len(data.RequestedUsers) == 0 {
		return false, nil // no reviewers were found (not contributing)
	}
	return true, nil
}

func getAuthToken() (string, error) {
	githubTokenVar := os.Getenv("GITHUB_TOKEN")
	if githubTokenVar != "" {
		log.Println("Using Github token from environment variable.")
		return githubTokenVar, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "reading user home directory failed")
	}

	githubTokenPath := filepath.Join(homeDir, ".elastic/github.token")
	token, err := ioutil.ReadFile(githubTokenPath)
	if err != nil {
		return "", errors.Wrapf(err, "reading Github token file failed (path: %s)", githubTokenPath)
	}
	log.Println("Using Github token from file.")
	return strings.TrimSpace(string(token)), nil
}

func buildPullRequestRequestBody(title, username, branchName, description string) ([]byte, error) {
	requestBody := map[string]interface{}{
		"title":                 title,
		"head":                  fmt.Sprintf("%s:%s", username, branchName),
		"base":                  "snapshot",
		"body":                  description,
		"maintainer_can_modify": true,
	}

	m, err := json.Marshal(&requestBody)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling request body failed")
	}
	return m, nil
}

func buildPullRequestReviewersRequestBody(reviewer string) ([]byte, error) {
	var requestBody map[string]interface{}

	if i := strings.Index(reviewer, "/"); i > -1 {
		requestBody = map[string]interface{}{"team_reviewers": []string{reviewer[i+1:]}}
	} else {
		requestBody = map[string]interface{}{"reviewers": []string{reviewer}}
	}

	m, err := json.Marshal(&requestBody)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling request body failed")
	}
	return m, nil
}

func buildPullRequestTitle(packageName, packageVersion string) string {
	return fmt.Sprintf(`[snapshot] Update "%s" integration to version %s`, packageName, packageVersion)
}

func buildPullRequestDiffURL(username, commitHash string) string {
	return fmt.Sprintf("https://github.com/%s/package-storage/commit/%s", username, commitHash)
}

func buildPullRequestDescription(packageName, packageVersion, diffURL string) string {
	return fmt.Sprintf("This PR updates `%s` integration to version %s.\n\nChanges: %s", packageName,
		packageVersion, diffURL)
}

func checkIfPullRequestAlreadyOpen(err error, packageName, packageVersion string) (bool, error) {
	if err != nil {
		return false, err
	}

	authToken, err := getAuthToken()
	if err != nil {
		return false, errors.Wrap(err, "fetching auth token failed")
	}

	expectedTitle := buildPullRequestTitle(packageName, packageVersion)
	q := url.QueryEscape(fmt.Sprintf(`repo:elastic/package-storage base:snapshot is:pr is:open in:title "%s"`, expectedTitle))

	request, err := http.NewRequest("GET", "https://api.github.com/search/issues?q="+q, nil)
	if err != nil {
		return false, errors.Wrap(err, "creating new HTTP request failed")
	}

	request.Header.Add("Authorization", fmt.Sprintf("token %s", authToken))
	request.Header.Add("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, errors.Wrap(err, "making HTTP call failed")
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return false, fmt.Errorf("unexpected status code return while opening a pull request: %d", response.StatusCode)
	}

	var data searchIssuesResponse
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, errors.Wrap(err, "can't read response body")
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return false, errors.Wrap(err, "unmarshalling response failed")
	}

	for _, k := range data.Items {
		if k.Title == expectedTitle {
			return true, nil
		}
	}
	return false, nil
}
