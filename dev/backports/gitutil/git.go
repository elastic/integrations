// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package gitutil

import (
	"os"
	"os/exec"
)

// Run runs a git command forwarding stdout and stderr to the terminal.
func Run(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Output runs a git command and returns its stdout as a string.
func Output(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	return string(out), err
}
