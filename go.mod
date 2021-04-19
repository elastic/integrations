module github.com/elastic/integrations

go 1.12

replace (
	github.com/docker/distribution => github.com/docker/distribution v0.0.0-20191216044856-a8371794149d
	github.com/docker/docker => github.com/moby/moby v17.12.0-ce-rc1.0.20200618181300-9dc6525e6118+incompatible
)

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/elastic/elastic-package v0.0.0-20210419162203-09854a6e8d57
	github.com/elastic/package-registry v0.17.0
	github.com/magefile/mage v1.11.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	gopkg.in/yaml.v2 v2.4.0
)
