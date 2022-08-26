#!/bin/bash

# Installs the elasticsearch package and attach an integration to the running Agent.
# The package policy (./package-policy.json) we attach to the agent policy has
# quite a few hardcoded values that we could potentially generate dynamically. The
# most important one is the agent policy. We're currently relying on the Agent installed
# by the `elastic-package stack` command but ideally we'd create a dedicated, standalone
# agent that we can fully control.

set -e

eval "$(elastic-package stack shellinit)"

script_dir=$(dirname ${BASH_SOURCE[0]})

package_version=`cat $script_dir/../../manifest.yml | sed -nr 's/^version: (.*)$/\1/p'`
es_service_container=`docker ps --filter "publish=9201" --format "{{print .Names}}"`
elastic_agent_logs_dir=/tmp/service_logs
policy_name=script-generated-elasticsearch-policy
package_policy_file=$script_dir/package-policy.json
kibana_host=$ELASTIC_PACKAGE_KIBANA_HOST

# these are the values of the es service started by `elastic-package service up`
elasticsearch_host=http://$es_service_container:9200
username=elastic
password=changeme

if [[ -z $es_service_container ]]; then
  echo No elasticsearch service found. Run "elastic-package service up -v" in the elasticsearch package to start the service
  exit 1
fi

echo Found elasticsearch service "$es_service_container"

elastic-package install

policy=`cat $package_policy_file |
  sed "s~__PACKAGE_VERSION__~$package_version~g" |
  sed "s~__INTEGRATION_POLICY_NAME__~$policy_name~g" |
  sed "s~__ELASTICSEARCH_HOST__~$elasticsearch_host~g" |
  sed "s~__ELASTICSEARCH_USERNAME__~$username~g" |
  sed "s~__ELASTICSEARCH_PASSWORD__~$password~g" |
  sed "s~__ELASTIC_AGENT_LOGS_DIR__~$elastic_agent_logs_dir~g"`

echo Attaching elasticsearch to Agent policy

curl --insecure -Ss -u $username:$password -X POST $kibana_host/api/fleet/package_policies \
  -H "kbn-xsrf: 1" \
  -H "Content-Type: application/json" \
  -d "$policy"
