// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package groups checks groups.yml, the taxonomy of integration groups
// (PROTOTYPE). A group is one tile per technology; each schema maps to the
// package a user installs for it.
package groups

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/elastic/integrations/dev/citools"
)

const (
	groupsFile  = "groups.yml"
	packagesDir = "packages"
)

type schema struct {
	Package string `yaml:"package"`
	Default bool   `yaml:"default"`
}

type group struct {
	Title       string            `yaml:"title"`
	Description string            `yaml:"description"`
	Icon        string            `yaml:"icon"`
	Schemas     map[string]schema `yaml:"schemas"`
}

type taxonomy struct {
	Groups map[string]group `yaml:"groups"`
}

// Check validates groups.yml against the packages directory.
func Check() error {
	return check(groupsFile, packagesDir)
}

func check(file, dir string) error {
	content, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", file, err)
	}
	var t taxonomy
	if err := yaml.Unmarshal(content, &t); err != nil {
		return fmt.Errorf("parsing %s: %w", file, err)
	}

	pkgs, err := citools.ListPackagesWithNames(dir)
	if err != nil {
		return fmt.Errorf("listing packages in %s: %w", dir, err)
	}
	known := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		known[p.Name] = true
	}

	var problems []string
	memberOf := map[string][]string{}
	names := make([]string, 0, len(t.Groups))
	for name := range t.Groups {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		g := t.Groups[name]
		if g.Title == "" {
			problems = append(problems, fmt.Sprintf("group %q: title is required", name))
		}
		if len(g.Schemas) == 0 {
			problems = append(problems, fmt.Sprintf("group %q: at least one schema is required", name))
		}
		defaults := 0
		members := map[string]bool{}
		for schemaName, s := range g.Schemas {
			if s.Default {
				defaults++
			}
			if s.Package == "" {
				problems = append(problems, fmt.Sprintf("group %q: schema %q has no package", name, schemaName))
				continue
			}
			if !known[s.Package] {
				problems = append(problems, fmt.Sprintf("group %q: schema %q references package %q, not found under %s/", name, schemaName, s.Package, dir))
			}
			if !members[s.Package] {
				members[s.Package] = true
				memberOf[s.Package] = append(memberOf[s.Package], name)
			}
		}
		if (len(g.Schemas) > 1 && defaults != 1) || defaults > 1 {
			problems = append(problems, fmt.Sprintf("group %q: exactly one schema must set default: true, found %d", name, defaults))
		}
		if g.Icon == "" {
			problems = append(problems, fmt.Sprintf("group %q: icon is required", name))
		} else if !members[g.Icon] {
			problems = append(problems, fmt.Sprintf("group %q: icon %q is not a member package", name, g.Icon))
		}
	}

	for pkg, groups := range memberOf {
		if len(groups) > 1 {
			problems = append(problems, fmt.Sprintf("package %q is in more than one group: %s", pkg, strings.Join(groups, ", ")))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%s is invalid:\n%s", file, strings.Join(problems, "\n"))
	}
	return nil
}
