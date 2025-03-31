---
navigation_title: "Upload an integration"
mapped_pages:
  - https://www.elastic.co/guide/en/integrations-developer/current/upload-a-new-integration.html
---

# Upload an integration to Kibana [upload-a-new-integration]


{{fleet}} supports integration installation through direct upload as a means to support integration developers or users who have created custom integrations that they don’t want to commit upstream back to the [Elastic Integrations repository](https://github.com/elastic/integrations).

Direct upload can also be useful in air-gapped environments, by providing a way to update integrations without needing to update a self-hosted package registry.


## Local development [upload-integration-local]

If you’ve followed the local development steps in [*Build an integration*](/extend/build-new-integration.md), upload your integration to Kibana with the following command:

```bash
elastic-package install --zip /path/to/my/custom-integration
```

For more information, see [`elastic-package install`](/extend/elastic-package.md#elastic-package-install).


## Production deployment [upload-integration-production]

To upload your integration to a production deployment, first zip the package:

```bash
$ cd /path/to/my/custom-integration
$ elastic-package build
```

You can now use the Kibana API to upload your integration:

```bash
$ curl -XPOST \
  -H 'content-type: application/zip' \
  -H 'kbn-xsrf: true' \
  http://your.kibana.host/api/fleet/epm/packages \
  -u {username}:{password} \
  --data-binary @my-custom-integration.zip
```

More information on this endpoint is available in the [Fleet API Reference](https://www.elastic.co/guide/en/fleet/current/fleet-apis.html).

