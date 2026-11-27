# Kibana connector specs

Proof of concept package. Not for release.

It holds declarative connector specs (YAML) for the Kibana connector catalog.
Kibana downloads this package from the Elastic Package Registry, checks the signature, and registers each spec as a connector type.
The Fleet plugin is not used.

Layout:

- `connector_specs/<connector>/<spec version>.yaml`: 1 file per spec version.

Known limit: the package spec does not allow the `connector_specs/` folder today, so `elastic-package lint` fails.
Build with `elastic-package build --zip --sign --skip-validation`.
