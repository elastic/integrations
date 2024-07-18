// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package teamlabels

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	teamlabelsPath = ".github/team_labels"
)

type githubTeamLabels struct {
	tlabels map[string]string
	path    string
}

func GetTeamLabels() (map[string]string, error) {
	return GetTeamLabelsFromPath(teamlabelsPath)
}

func GetTeamLabelsFromPath(path string) (map[string]string, error) {
	githubTeamLabels, err := readTeamLabels(path)
	if err != nil {
		return nil, err
	}
	return githubTeamLabels.tlabels, nil
}

func readTeamLabels(teamlabelsPath string) (*githubTeamLabels, error) {
	f, err := os.Open(teamlabelsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %q: %w", teamlabelsPath, err)
	}
	defer f.Close()

	ghTeamLabels := githubTeamLabels{
		tlabels: make(map[string]string),
		path:    teamlabelsPath,
	}

	scanner := bufio.NewScanner(f)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		teamHandle, teamLabel, found := strings.Cut(line, " ")
		if !found || !isValidTeamHandle(teamHandle) || !isValidTeamLabel(teamLabel) {
			return nil, fmt.Errorf("%s file wrongly formatted", teamlabelsPath)
		}

		path, label := teamHandle, teamLabel

		// It is ok to overwrite because latter lines have precedence in these files.
		ghTeamLabels.tlabels[path] = label
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return &ghTeamLabels, nil
}

func isValidTeamHandle(teamHandle string) bool {
	return strings.HasPrefix(teamHandle, "@")
}

func isValidTeamLabel(teamLabel string) bool {
	return strings.HasPrefix(strings.ToLower(teamLabel), "team:")
}
