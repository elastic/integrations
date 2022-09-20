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
	reportExt         = ".xml"
	resultNoChange    = ":+1:"
	resultImprovement = ":green_heart:"
	resultWorse       = ":broken_heart:"
	tpl               = `### :rocket: Benchmarks report
{{range $package, $reports := .}}
{{if hasPrintableReports $reports}}
#### Package ` + "`" + `{{$package}}` + "`" + ` {{getReportsSummary $reports}}
<details>
<summary>Expand to view</summary>

Data stream | Previous EPS | New EPS | Diff (%) | Result
----------- | ------------ | ------- | -------- | ------
{{range $reports}}{{$result := getResult .Old .Percentage}}{{if isPrintable $result}}` +
		"`" + `{{.DataStream}}` + "`" +
		` | {{.Old}} | {{.New}} | {{.Diff}} ({{if gt .Old 0.0}}{{.Percentage}}{{else}} - {{end}}%) | {{$result}}
{{end}}{{end}}</details>{{end}}
{{end}}

To see the full report comment with ` + "`/test benchmark fullreport`\n"
)

type options struct {
	sourceDir  string
	targetDir  string
	fullReport bool
	threshold  float64
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

func GetBenchReport(sourceDir, targetDir string, threshold float64, fullReport bool) ([]byte, error) {
	opts := options{
		sourceDir:  sourceDir,
		targetDir:  targetDir,
		threshold:  threshold,
		fullReport: fullReport,
	}

	if err := opts.validate(); err != nil {
		return nil, err
	}

	tpl, err := getReportTpl(opts)
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
		pkg, ds := srcRes.getPackageAndDatastream()
		var tgtRes BenchmarkResult
		if tgtEntry, found := tgtResults[pkg]; found {
			if ds, found := tgtEntry[ds]; found {
				tgtRes, err = readResult(opts.targetDir, ds)
				if err != nil {
					return nil, fmt.Errorf("reading source result: %w", err)
				}
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
	if r.Old > 0 {
		r.Percentage = roundFloat64((r.Diff / r.Old) * 100)
	}

	return r
}

func roundFloat64(v float64) float64 {
	return math.Round(v*100) / 100
}

func getReportTpl(opts options) (*template.Template, error) {
	return template.New("result").Funcs(map[string]interface{}{
		"getResult": func(oldValue, p float64) string {
			return getResult(opts.threshold, oldValue, p)
		},
		"isPrintable": func(result string) bool {
			return isPrintable(opts.fullReport, result)
		},
		"getReportsSummary": func(reports []report) string {
			sum := map[string]int{}
			for _, r := range reports {
				sum[getResult(opts.threshold, r.Old, r.Percentage)] += 1
			}
			return fmt.Sprintf(
				"%s(%d) %s(%d) %s(%d)",
				resultNoChange, sum[resultNoChange],
				resultImprovement, sum[resultImprovement],
				resultWorse, sum[resultWorse],
			)
		},
		"hasPrintableReports": func(reports []report) bool {
			for _, r := range reports {
				if isPrintable(opts.fullReport, getResult(opts.threshold, r.Old, r.Percentage)) {
					return true
				}
			}
			return false
		},
	}).Parse(tpl)
}

func getResult(threshold, oldValue, p float64) string {
	switch {
	default:
		fallthrough
	case oldValue == 0:
		return resultNoChange
	case p > threshold:
		return resultImprovement
	case p < 0 && p < (threshold*-1):
		return resultWorse
	}
}

func isPrintable(fullReport bool, result string) bool {
	if fullReport {
		return true
	}
	return result == resultWorse
}
