package issuesreporter

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type testSuites struct {
	XMLName xml.Name    `xml:"testsuites"`
	Suites  []testSuite `xml:"testsuite"`
}
type testSuite struct {
	Comment string `xml:",comment"`

	Name        string `xml:"name,attr"`
	NumTests    int    `xml:"tests,attr,omitempty"`
	NumFailures int    `xml:"failures,attr,omitempty"`
	NumErrors   int    `xml:"errors,attr,omitempty"`
	NumSkipped  int    `xml:"skipped,attr,omitempty"`

	Suites []testSuite `xml:"testsuite,omitempty"`
	Cases  []testCase  `xml:"testcase,omitempty"`
}
type testCase struct {
	Name          string  `xml:"name,attr"`
	ClassName     string  `xml:"classname,attr"`
	TimeInSeconds float64 `xml:"time,attr"`

	Error   string   `xml:"error,omitempty"`
	Failure string   `xml:"failure,omitempty"`
	Skipped *skipped `xml:"skipped,omitempty"`
}

type skipped struct {
	Message string `xml:"message,attr"`
}

func (t testCase) String() string {
	var sb strings.Builder
	sb.WriteString(t.Name)
	sb.WriteString(" in ")
	sb.WriteString(t.ClassName)
	return sb.String()
}

func testFailures(path string) ([]testCase, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var results testSuites

	err = xml.Unmarshal(contents, &results)
	if err != nil {
		return []testCase{}, fmt.Errorf("failed to unmarshal file %s: %w", path, err)
	}

	failures := []testCase{}
	for _, testsuite := range results.Suites {
		for _, testcase := range testsuite.Cases {
			if testcase.Failure != "" {
				failures = append(failures, testcase)
			}
			if testcase.Error != "" {
				failures = append(failures, testcase)
			}
		}
	}

	return failures, nil
}
