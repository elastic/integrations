We are building new integration `cloud_defend_otel`, an elastic package with type input and OTEL receiver. I have already created a skeleton in `./packages/cloud_defend_otel` by using `elastic-package`.
We are moving parts of functionality from an existing integration @packages/cloud_defend/manifest.yml.

Create a plan to build the following:
 * add only two datastreams: for logs and files
 * all the datastreams should have type `log`
 * no need to add `policy_templates` for now
 * plan to build an OTEL collector input package
 * OTEL collector should receive data from `otlpreceiver` and send it to elasticsearch as recommended in the docs.
 * the new package should have policy and system tests, check how it is done in `kafka_input_otel`
 * for system tests we will write a golang generator, which will push the data to our OTEL collector. Source @packages/kafka_input_otel/_dev/deploy/docker/generator/main.go as an example.

Interview me if something is not clear our you find we need to include more functionality.

Read the following files as guidance:
 - @docs/extend/system-testing.md
 - @docs/extend/otel-input-packages.md

Read the following packages as examples:
 - @packages/hostmetrics_input_otel
 - @packages/kafka_input_otel

Write the plan into `./packages/cloud_defend_otel/plan.md` file.