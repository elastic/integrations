// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// File partially copied from elastic-package.

package coverage

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
)

// GenericCoverage is the root element for a Cobertura XML report.
type GenericCoverage struct {
	XMLName   xml.Name       `xml:"coverage"`
	Version   int64          `xml:"version,attr"`
	Files     []*GenericFile `xml:"file"`
	Timestamp int64          `xml:"-"`
	TestType  string         `xml:",comment"`
}

type GenericFile struct {
	Path  string         `xml:"path,attr"`
	Lines []*GenericLine `xml:"lineToCover"`
}

type GenericLine struct {
	LineNumber int64 `xml:"lineNumber,attr"`
	Covered    bool  `xml:"covered,attr"`
}

func (c *GenericCoverage) Bytes() ([]byte, error) {
	out, err := xml.MarshalIndent(&c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unable to format test results as Coverage: %w", err)
	}

	var buffer bytes.Buffer
	buffer.WriteString(xml.Header)
	buffer.WriteString("\n")
	buffer.Write(out)
	return buffer.Bytes(), nil
}

func (c *GenericFile) merge(b *GenericFile) error {
	// Merge files
	for _, coverageLine := range b.Lines {
		found := false
		foundId := 0
		for idx, existingLine := range c.Lines {
			if existingLine.LineNumber == coverageLine.LineNumber {
				found = true
				foundId = idx
				break
			}
		}
		if !found {
			c.Lines = append(c.Lines, coverageLine)
		} else {
			c.Lines[foundId].Covered = c.Lines[foundId].Covered || coverageLine.Covered
		}
	}
	return nil
}

// merge merges two coverage reports.
func (c *GenericCoverage) Merge(other *GenericCoverage) error {
	// Merge files
	for _, coverageFile := range other.Files {
		var target *GenericFile
		for _, existingFile := range c.Files {
			if existingFile.Path == coverageFile.Path {
				target = existingFile
				break
			}
		}
		if target != nil {
			if err := target.merge(coverageFile); err != nil {
				return err
			}
		} else {
			c.Files = append(c.Files, coverageFile)
		}
	}
	return nil
}

func ReadGenericCoverage(path string) (*GenericCoverage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open failed: %w", err)
	}
	defer f.Close()

	dec := xml.NewDecoder(f)

	var coverage GenericCoverage
	err = dec.Decode(&coverage)
	if err != nil {
		return nil, fmt.Errorf("xml decode failed: %w", err)
	}

	return &coverage, nil
}

func MergeGenericCoverageFiles(paths []string, output string) error {
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("cannot open file %s to write merged coverage: %w", output, err)
	}
	defer f.Close()

	var coverage *GenericCoverage
	for _, path := range paths {
		c, err := ReadGenericCoverage(path)
		if err != nil {
			return fmt.Errorf("failed to read coverage from %s: %w", path, err)
		}
		if coverage == nil {
			coverage = c
			continue
		}
		err = coverage.Merge(c)
		if err != nil {
			return fmt.Errorf("failed to merge coverage from %s: %w", path, err)
		}
	}

	d, err := coverage.Bytes()
	if err != nil {
		return fmt.Errorf("failed to encode merged coverage: %w", err)
	}

	_, err = f.Write(d)
	if err != nil {
		return fmt.Errorf("cannot write merged coverage to %s: %w", output, err)
	}

	return nil
}
