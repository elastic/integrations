#!/bin/bash

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
cat << EOF
Makes the selected dashboards editable on the cluster defined in secrets.yml
Note: Export the dashboards after editing.

EOF

  exit 0
fi

summon -p ssm elastic-package edit dashboards

