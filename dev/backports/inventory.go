// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backports

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type inventory struct {
	Backports []entry `yaml:"backports"`
}

type entry struct {
	Package         string  `yaml:"package"`
	Branch          string  `yaml:"branch"`
	BaseVersion     string  `yaml:"base_version"`
	BaseCommit      string  `yaml:"base_commit"`
	MaintainedUntil *string `yaml:"maintained_until"` // null → nil; "YYYY-MM-DD" → &string
	Archived        *bool   `yaml:"archived"`          // nil when field is absent
}

const maintainedUntilLayout = "2006-01-02"

// ValidateInventory reads the .backports.yml inventory at path and returns a
// combined error listing every schema violation found across all entries.
func ValidateInventory(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading inventory: %w", err)
	}

	var inv inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return fmt.Errorf("parsing inventory: %w", err)
	}

	var errs []error
	for i, e := range inv.Backports {
		id := fmt.Sprintf("entry[%d]", i)
		if e.Branch != "" {
			id = fmt.Sprintf("branch %q", e.Branch)
		}

		if e.Package == "" {
			errs = append(errs, fmt.Errorf("%s: missing required field 'package'", id))
		}
		if e.Branch == "" {
			errs = append(errs, fmt.Errorf("%s: missing required field 'branch'", id))
		}
		if e.BaseVersion == "" {
			errs = append(errs, fmt.Errorf("%s: missing required field 'base_version'", id))
		}
		if e.BaseCommit == "" {
			errs = append(errs, fmt.Errorf("%s: missing required field 'base_commit'", id))
		}
		if e.Archived == nil {
			errs = append(errs, fmt.Errorf("%s: missing required field 'archived'", id))
		}
		if e.MaintainedUntil != nil {
			if _, parseErr := time.Parse(maintainedUntilLayout, *e.MaintainedUntil); parseErr != nil {
				errs = append(errs, fmt.Errorf("%s: invalid maintained_until %q: must be YYYY-MM-DD", id, *e.MaintainedUntil))
			}
		}
	}

	return errors.Join(errs...)
}
