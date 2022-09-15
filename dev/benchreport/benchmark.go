// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package benchreport

import "strconv"

type BenchmarkResult struct {
	// Parameters used for this benchmark.
	Parameters []BenchmarkValue `xml:"parameter"`

	// Tests holds the results for the benchmark.
	Tests []BenchmarkTest `xml:"test"`
}

func (r *BenchmarkResult) getEPS() float64 {
	for _, test := range r.Tests {
		for _, res := range test.Results {
			if res.Name == "eps" {
				v, _ := strconv.ParseFloat(res.Value, 64)
				return v
			}
		}
	}
	return 0
}

func (r *BenchmarkResult) getPackageAndDatastream() (string, string) {
	var pkg, ds string
	for _, p := range r.Parameters {
		switch p.Name {
		case "package":
			pkg = p.Value
		case "data_stream":
			ds = p.Value
		}
	}
	return pkg, ds
}

// BenchmarkTest models a particular test performed during a benchmark.
type BenchmarkTest struct {
	// Name of this test.
	Name string `xml:"name,attr"`
	// Results of the test.
	Results []BenchmarkValue `xml:"result"`
}

// BenchmarkValue represents a value (result or parameter)
// with an optional associated unit.
type BenchmarkValue struct {
	// Name of the value.
	Name string `xml:"name,attr"`

	// Value is of any type, usually string or numeric.
	Value string `xml:"value"`
}
