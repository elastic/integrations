package issuesreporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorsFromTest(t *testing.T) {
	cases := []struct {
		title     string
		xmlFolder string
		expected  []PackageError
	}{
		{
			title:     "read XML files",
			xmlFolder: "testdata",
			expected: []PackageError{
				{
					testCase: testCase{
						Name:          "system test: default",
						ClassName:     "cisco_umbrella.log",
						TimeInSeconds: 1368.349501429,
						Failure:       "could not find hits in logs-cisco_umbrella.log-ep data stream",
					},
					Package:    "cisco_umbrella",
					Serverless: false,
				},
				{
					testCase: testCase{
						Name:          "pipeline test: test-fortinet-7-4.log",
						ClassName:     "fortinet_fortigate.log",
						TimeInSeconds: 0.209966522,
						Failure: `test case failed: Expected results are different from actual ones: --- want
+++ got
@@ -2302,7 +2302,6 @@
                 "preserve_original_event"
             ],
             "url": {
-                "extension": "fortianalyzer/setting",
                 "path": "/api/v2/cmdb/log.fortianalyzer/setting",
                 "query": "vdom=root"
             }
`,
					},
					Package:    "fortinet_fortigate",
					Serverless: false,
				},
				{
					testCase: testCase{
						Name:          "system test: mssql",
						ClassName:     "sql_input.",
						TimeInSeconds: 34.296986222,
						Failure:       "one or more errors found in documents stored in metrics-sql.sql-12466 data stream: [0] found error.message in event: cannot open connection: testing connection: mssql: login error: Login failed for user 'SA'.",
					},
					Package:    "sql_input",
					Serverless: false,
				},
				{
					testCase: testCase{
						Name:          "system test: mysql",
						ClassName:     "sql_input.",
						TimeInSeconds: 34.25843055,
						Error:         "one or more errors found in documents stored in metrics-sql.sql-98584 data stream: [0] found error.message in event: cannot open connection: testing connection: dial tcp 172.21.0.6:3306: connect: connection refused",
					},
					Package:    "sql_input",
					Serverless: false,
				},
				{
					testCase: testCase{
						Name:          "system test: default",
						ClassName:     "test.metrics",
						TimeInSeconds: 1368.349501429,
						Error:         "could not find hits in logs-test.metrics-ep data stream",
					},
					Package:    "test",
					Serverless: false,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			errors, err := errorsFromTests(checkOptions{
				ResultsPath:  c.xmlFolder,
				Serverless:   false,
				StackVersion: "",
				BuildURL:     "",
			})
			require.NoError(t, err)

			assert.Len(t, errors, len(c.expected))

			assert.Equal(t, errors, c.expected)
		})
	}
}

func TestErrorDataStream(t *testing.T) {
	cases := []struct {
		title     string
		xmlFolder string
		expected  []string
	}{
		{
			title:     "read XML files",
			xmlFolder: "testdata",
			expected: []string{
				"log",
				"log",
				"", // input package
				"", // input package
				"metrics",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			errors, err := errorsFromTests(checkOptions{
				ResultsPath:  c.xmlFolder,
				Serverless:   false,
				StackVersion: "",
				BuildURL:     "",
			})
			require.NoError(t, err)

			assert.Len(t, errors, len(c.expected))

			dataStreams := []string{}
			for _, e := range errors {
				dataStreams = append(dataStreams, e.DataStream())
			}
			assert.Equal(t, dataStreams, c.expected)
		})
	}
}
