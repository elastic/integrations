#!/bin/bash

# based on https://github.com/open-telemetry/opentelemetry-proto/blob/d3fb76d70deb0874692bd0ebe03148580d85f3bb/examples/metrics.json
create_metric_document() {
    local service_name="my.service.${1}"
    local timestampns=""
    timestampns="$(date +%s)000000000"
    local random_value=$((RANDOM % 100))
    local target_folder="/tmp/metrics-${service_name}"
    mkdir -p "${target_folder}"
    local filename="${target_folder}/doc-${random_value}.json"
    cat <<EOF | tr -d '\n' > "${filename}"
{
  "resourceMetrics": [
    {
      "resource": {
        "attributes": [
          {
            "key": "service.name",
            "value": {
              "stringValue": "${service_name}"
            }
          }
        ]
      },
      "scopeMetrics": [
        {
          "scope": {
            "name": "my.library",
            "version": "1.0.0",
            "attributes": [
              {
                "key": "my.scope.attribute",
                "value": {
                  "stringValue": "some scope attribute"
                }
              }
            ]
          },
          "metrics": [
            {
              "name": "my.counter",
              "unit": "1",
              "description": "I am a Counter",
              "sum": {
                "aggregationTemporality": 1,
                "isMonotonic": true,
                "dataPoints": [
                  {
                    "asDouble": 5,
                    "startTimeUnixNano": "$timestampns",
                    "timeUnixNano": "$timestampns",
                    "attributes": [
                      {
                        "key": "my.counter.attr",
                        "value": {
                          "stringValue": "some value"
                        }
                      }
                    ]
                  }
                ]
              }
            },
            {
              "name": "my.gauge",
              "unit": "1",
              "description": "I am a Gauge",
              "gauge": {
                "dataPoints": [
                  {
                    "asDouble": 10,
                    "timeUnixNano": "$timestampns",
                    "attributes": [
                      {
                        "key": "my.gauge.attr",
                        "value": {
                          "stringValue": "some value"
                        }
                      }
                    ]
                  }
                ]
              }
            },
            {
              "name": "my.histogram",
              "unit": "1",
              "description": "I am a Histogram",
              "histogram": {
                "aggregationTemporality": 1,
                "dataPoints": [
                  {
                    "startTimeUnixNano": "$timestampns",
                    "timeUnixNano": "$timestampns",
                    "count": 2,
                    "sum": 2,
                    "bucketCounts": [1,1],
                    "explicitBounds": [1],
                    "min": 0,
                    "max": 2,
                    "attributes": [
                      {
                        "key": "my.histogram.attr",
                        "value": {
                          "stringValue": "some value"
                        }
                      }
                    ]
                  }
                ]
              }
            },
            {
              "name": "my.exponential.histogram",
              "unit": "1",
              "description": "I am an Exponential Histogram",
              "exponentialHistogram": {
                "aggregationTemporality": 1,
                "dataPoints": [
                  {
                    "startTimeUnixNano": "$timestampns",
                    "timeUnixNano": "$timestampns",
                    "count": 3,
                    "sum": 10,
                    "scale": 0,
                    "zeroCount": 1,
                    "positive": {
                      "offset": 1,
                      "bucketCounts": [0,2]
                    },
                    "min": 0,
                    "max": 5,
                    "zeroThreshold": 0,
                    "attributes": [
                      {
                        "key": "my.exponential.histogram.attr",
                        "value": {
                          "stringValue": "some value"
                        }
                      }
                    ]
                  }
                ]
              }
            }
          ]
        }
      ]
    }
  ]
}
EOF

    cat "${filename}" | tr -d '\n'
    # Required to add a newline to the end of the output
    echo ""
    rm -rf "${target_folder}" 2> /dev/null
}
