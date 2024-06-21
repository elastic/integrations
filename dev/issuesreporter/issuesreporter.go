package issuesreporter

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type PackageError struct {
	testCase
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
	sb.WriteString(p.Package())
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

func (p PackageError) Package() string {
	values := strings.Split(p.testCase.ClassName, ".")
	return values[0]
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
	ghRunner := NewGithubRunner(GhRunnerOptions{DryRun: true})
	for _, e := range packageErrors {
		r := ResultsFormatter{e}
		fmt.Printf("Title: %q\n", r.Title())
		fmt.Printf("Description:\n%s\n", r.Description())

		ghIssue := NewGithubIssue(GithubIssueOptions{
			Title:       r.Title(),
			Description: r.Description(),
			Labels:      []string{"failed-test", "automation"},
			Repository:  "elastic/integrations",
		})

		ctx := context.TODO()
		found, issue, err := ghRunner.Exists(ctx, *ghIssue)
		if err != nil {
			return fmt.Errorf("failed to check if issue exists: %w", err)
		}
		fmt.Printf("Issue found: %t (%d)\n", found, issue.Number())
		if !found {
			// create issue
			err := ghRunner.Create(ctx, *ghIssue)
			if err != nil {
				log.Printf("Failed to create issue: %s", err)
			}
			continue
		}
		// update issue

		return nil
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
		fmt.Println("Reading file:", path)
		cases, err := testFailures(path)
		if err != nil {
			return err
		}

		for _, c := range cases {
			packageErrors = append(packageErrors, PackageError{
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
