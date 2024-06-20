package issuesreporter

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type PackageError struct {
	testCase
	Package      string
	Serverless   bool
	StackVersion string
	BuildURL     string
}

func (p PackageError) String() string {
	var sb strings.Builder

	if p.Serverless {
		sb.WriteString("[Serverless] ")
	}
	if p.StackVersion != "" {
		sb.WriteString("[Stack ")
		sb.WriteString(p.StackVersion)
		sb.WriteString("] ")
	}
	sb.WriteString("[")
	sb.WriteString(p.Package)
	sb.WriteString("] ")
	sb.WriteString("Failing test daily: ")
	sb.WriteString(p.testCase.String())

	return sb.String()
}

func (p PackageError) DataStream() string {
	values := strings.Split(p.testCase.ClassName, ".")
	if len(values) < 2 {
		return ""
	}
	return values[1]
}

type checkOptions struct {
	ResultsPath  string
	Serverless   bool
	StackVersion string
	BuildURL     string
}

func Check(resultsPath, buildURL, stackVersion string, serverless bool) error {
	fmt.Println("path: ", resultsPath)
	packageErrors, err := errorsFromTests(checkOptions{
		ResultsPath:  resultsPath,
		Serverless:   serverless,
		StackVersion: stackVersion,
		BuildURL:     buildURL,
	})
	if err != nil {
		return err
	}
	for _, e := range packageErrors {
		fmt.Printf("Failures found for %s\n", e.Package)
		if e.Failure != "" {
			fmt.Printf("- (failure) %s (%s): %s\n", e.Name, e.ClassName, e.Failure)
		}
		if e.Error != "" {
			fmt.Printf("- (error) %s (%s): %s\n", e.Name, e.ClassName, e.Error)
		}
	}
	for _, e := range packageErrors {
		r := ResultsFormatter{e}
		fmt.Printf("Title: %q\n", r.Title())
		fmt.Printf("Description:\n%s\n", r.Description())
	}
	return nil
}

func errorsFromTests(options checkOptions) ([]PackageError, error) {
	var packageErrors []PackageError
	err := filepath.Walk(options.ResultsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".xml" {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		fmt.Println("File to get read: ", path)
		packageName, err := getPackageFromPath(filepath.Base(path))
		if err != nil {
			return err
		}
		cases, err := testFailures(path)
		if err != nil {
			return err
		}

		for _, c := range cases {
			packageErrors = append(packageErrors, PackageError{
				Package:      packageName,
				Serverless:   options.Serverless,
				StackVersion: options.StackVersion,
				BuildURL:     options.BuildURL,
				testCase:     c,
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to look for errors: %w", err)
	}

	return packageErrors, nil
}

func getPackageFromPath(path string) (string, error) {
	pattern := "^(?P<Package>.*)_\\d+.xml"
	regex := regexp.MustCompile(pattern)
	if matches := regex.FindStringSubmatch(path); len(matches) > 1 {
		return matches[1], nil
	}
	return "", fmt.Errorf("failed to find package name from file %s", path)
}
