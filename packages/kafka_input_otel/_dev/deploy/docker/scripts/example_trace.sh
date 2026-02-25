#!/bin/bash

# based on https://github.com/open-telemetry/opentelemetry-proto/blob/d3fb76d70deb0874692bd0ebe03148580d85f3bb/examples/metrics.json
create_trace_document() {
    local service_name="my.service.${1}"
    local timestampns=""
    timestampns="$(date +%s)000000000"
    local random_value=$((RANDOM % 100))
    local target_folder="/tmp/traces-${service_name}"
    mkdir -p "${target_folder}"
    local filename="${target_folder}/doc-${random_value}.json"
    cat <<EOF | tr -d '\n' > "${filename}"
{
  "resourceSpans": [
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
      "scopeSpans": [
        {
          "scope": {
            "name": "${service_name}",
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
          "spans": [
            {
              "traceId": "5B8EFFF798038103D269B633813FC60C",
              "spanId": "EEE19B7EC3C1B174",
              "parentSpanId": "EEE19B7EC3C1B173",
              "name": "I'm a server span",
              "startTimeUnixNano": "${timestampns}",
              "endTimeUnixNano": "${timestampns}",
              "kind": 2,
              "attributes": [
                {
                  "key": "my.span.attr",
                  "value": {
                    "stringValue": "some value"
                  }
                }
              ]
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

