// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package benchreport

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"text/template"
)

const (
	reportExt = ".xml"
	tpl       = `### :rocket: Benchmarks report
{{range $package, $reports := .}}
#### Package ` + "`" + `{{$package}}` + "`" + `

Data stream | Previous EPS | New EPS | Diff (%) | Result
----------- | ------------ | ------- | -------- | ------
{{range $reports}}` + "`" + `{{.DataStream}}` + "`" + ` | {{.Old}} | {{.New}} | {{.Diff}} ({{.Percentage}}%) | {{getResult .Old .Percentage}}
{{end}}{{end}}`
)

type options struct {
	sourceDir string
	targetDir string
	threshold float64
}

func (o *options) validate() error {
	if _, err := os.Stat(o.sourceDir); err != nil {
		return fmt.Errorf("stat file failed (path: %s): %w", o.sourceDir, err)
	}

	if _, err := os.Stat(o.targetDir); err != nil {
		return fmt.Errorf("stat file failed (path: %s): %w", o.targetDir, err)
	}

	return nil
}

type report struct {
	Package    string
	DataStream string
	Old        float64
	New        float64
	Diff       float64
	Percentage float64
}

func GetBenchReport(sourceDir, targetDir string, threshold float64) ([]byte, error) {
	opts := options{
		sourceDir: sourceDir,
		targetDir: targetDir,
		threshold: threshold,
	}

	if err := opts.validate(); err != nil {
		return nil, err
	}

	tpl, err := getReportTpl(opts.threshold)
	if err != nil {
		return nil, err
	}

	reports, err := run(opts)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, reports); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func run(opts options) (map[string][]report, error) {
	// get all results from source
	srcResults, err := listAllDirResults(opts.sourceDir)
	if err != nil {
		return nil, fmt.Errorf("listing source results failed: %w", err)
	}

	// get all results from target
	tgtResults, err := listAllDirResultsAsMap(opts.targetDir)
	if err != nil {
		return nil, fmt.Errorf("listing target results failed: %w", err)
	}

	// lookup source reports in target and compare
	reports := map[string][]report{}
	for _, entry := range srcResults {
		srcRes, err := readResult(opts.sourceDir, entry)
		if err != nil {
			return nil, fmt.Errorf("reading source result: %w", err)
		}

		pkg, _ := srcRes.getPackageAndDatastream()

		var tgtRes BenchmarkResult
		if tgtEntry, found := tgtResults[pkg]; found {
			tgtRes, err = readResult(opts.targetDir, tgtEntry)
			if err != nil {
				return nil, fmt.Errorf("reading source result: %w", err)
			}
		}

		report := createReport(srcRes, tgtRes)
		reports[report.Package] = append(reports[report.Package], report)
	}

	return reports, nil
}

func createReport(src, tgt BenchmarkResult) report {
	var r report
	r.Package, r.DataStream = src.getPackageAndDatastream()

	// we round all the values to 2 decimals approximations
	r.New = roundFloat64(src.getEPS())
	r.Old = roundFloat64(tgt.getEPS())
	r.Diff = roundFloat64(r.New - r.Old)
	r.Percentage = roundFloat64((r.Diff / r.New) * 100)

	return r
}

func roundFloat64(v float64) float64 {
	return math.Round(v*100) / 100
}

func getReportTpl(threshold float64) (*template.Template, error) {
	return template.New("result").Funcs(map[string]interface{}{
		"getResult": func(oldValue, p float64) string {
			switch {
			default:
				fallthrough
			case oldValue == 0:
				return ":+1:"
			case p > threshold:
				return ":broken_heart:"
			case p < 0 && p < (threshold*-1):
				return ":green_heart:"
			}
		},
	}).Parse(tpl)
}
