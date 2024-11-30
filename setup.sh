export ELASTIC_PACKAGE_KIBANA_HOST="https://bill-easton-test.kb.us-central1.gcp.cloud.es.io/"
export ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME="elastic_package"
export ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD="elastic_package"
export ELASTIC_PACKAGE_CA_CERT=""

elastic-package build && elastic-package install

pause 'Press [Enter] key to continue...'

elastic-package uninstall