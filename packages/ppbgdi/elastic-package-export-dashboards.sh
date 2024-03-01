#!/bin/bash

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
cat << EOF
Exports the selected dashboards and related assets from the cluster defined in secrets.yml
to the ./kibana directory.
Note: Re-install the package on the cluster to lock the dashboards again.
EOF

  exit 0
fi

summon -p ssm elastic-package export dashboards

