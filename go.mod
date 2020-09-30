module github.com/elastic/integrations

go 1.12

replace github.com/elastic/package-registry => github.com/mtojek/package-registry v0.2.1-0.20200930081928-2714a929f466

replace github.com/elastic/elastic-package => github.com/mtojek/elastic-package v0.0.0-20200928094850-a3fd7d3eedbe

replace github.com/elastic/package-spec/code/go => github.com/mtojek/package-spec/code/go v0.0.0-20200929092025-ae3660cc902c

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/elastic/elastic-package v0.0.0-20200921095517-7a811f6547c2
	github.com/elastic/package-registry v0.11.0
	github.com/magefile/mage v1.10.0
	github.com/pkg/errors v0.9.1
	gopkg.in/yaml.v2 v2.3.0
)
