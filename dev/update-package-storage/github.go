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

const pullRequestsPerPage = 30

type searchIssuesResponse struct {
	Items []pullRequest `json:"items"`
}

type pullRequest struct {
	Title string `json:"title"`
}

func openPullRequest(err error, options updateOptions, packageName, packageVersion, username, branchName, commitHash string) error {
	if err != nil {
		return err
	}

	if options.skipPullRequest {
		return nil
	}

	authToken, err := getAuthToken()
	if err != nil {
		return errors.Wrap(err, "fetching auth token failed")
	}

	title := buildPullRequestTitle(packageName, packageVersion)
	diffURL := buildPullRequestDiffURL(username, commitHash)
	description := buildPullRequestDescription(packageName, packageVersion, diffURL)

	requestBody, err := buildPullRequestRequestBody(title, username, branchName, description)
	if err != nil {
		return errors.Wrap(err, "building request body failed")
	}

	request, err := http.NewRequest("POST", "https://api.github.com/repos/elastic/package-storage/pulls", bytes.NewReader(requestBody))
	if err != nil {
		return errors.Wrap(err, "creating new HTTP request failed")
	}

	request.Header.Add("Authorization", fmt.Sprintf("token %s", authToken))
	request.Header.Add("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return errors.Wrap(err, "making HTTP call failed")
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		k, _ := ioutil.ReadAll(response.Body)
		log.Fatal(string(k))
		return fmt.Errorf("unexpected status code return while opening a pull request: %d", response.StatusCode)
	}
	return nil
}

func getAuthToken() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "reading user home directory failed")
	}

	githubTokenPath := filepath.Join(homeDir, ".elastic/github.token")
	token, err := ioutil.ReadFile(githubTokenPath)
	if err != nil {
		return "", errors.Wrapf(err, "reading Github token file failed (path: %s)", githubTokenPath)
	}
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
		k, _ := ioutil.ReadAll(response.Body)
		log.Fatal(string(k))
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
