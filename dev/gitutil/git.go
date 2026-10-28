// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package gitutil

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Git runs git commands in Dir. An empty Dir means the current working directory.
type Git struct{ Dir string }

// Run runs a git command forwarding stdout and stderr to the terminal.
func (g Git) Run(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.Dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Output runs a git command and returns its stdout as a string.
// On failure the returned error includes git's stderr output.
func (g Git) Output(args ...string) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Dir = g.Dir
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}
