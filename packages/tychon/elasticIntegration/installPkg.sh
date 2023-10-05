#!/bin/sh
$(elastic-package stack shellinit)
cd ./tychon
elastic-package uninstall
elastic-package clean
if elastic-package check ;then
  while read line; do
		if [[ $line == "version:"* ]]; then
			set -- $line
			version=$2
		fi
	done < manifest.yml
	docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_reg.yml down
	cp /root/elasticIntegration/build/packages/tychon-$version.zip /root/.elastic-package/stack/development/
	docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_reg.yml build
	docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_reg.yml up -d
	elastic-package install
fi
