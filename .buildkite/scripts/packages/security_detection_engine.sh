#!/bin/bash

set -euo pipefail

PACKAGE_VERSION=$(yq -r '.version' ./packages/security_detection_engine/manifest.yml)
EPR_INSTANCE_NAME="bk-epr-prebuilt-rules-oom-testing-$BUILDKITE_BUILD_NUMBER"
GCP_ZONE="us-west2-a"

buildkite-agent pipeline upload ./.buildkite/scripts/packages/security_detection_engine/pipeline.yml

# gcloud compute instances create "$EPR_INSTANCE_NAME" \
#     --zone=us-west2-a \
#     --machine-type=e2-small \
#     --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default \
#     # --maintenance-policy=MIGRATE \
#     --provisioning-model=STANDARD \
#     # --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/trace.append \
#     --tags=https-server \
#     --create-disk=auto-delete=yes,boot=yes,device-name=instance-20251031-131502,image="$EPR_VM_IMAGE",mode=rw,size=10,type=pd-standard \
#     --no-shielded-secure-boot \
#     --no-shielded-vtpm \
#     --no-shielded-integrity-monitoring \
#     --labels=goog-ec-src=vm_add-gcloud \
#     --reservation-affinity=any
#     --quiet
# echo "--- Deploy EPR instance: $EPR_INSTANCE_NAME (Mock)"

# Save and upload cloud-init configuration
# cat <<YAML > cloud-init.yaml
# package_update: true
# package_upgrade: true
# packages:
#   - docker.io
#   - openssl

# runcmd:
#   - mkdir -p /etc/package-registry/packages
#   - chmod 0777 /etc/package-registry/packages  

#   - mkdir -p /etc/package-registry/certs
#   - openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/package-registry/certs/package-registry.key -out /etc/package-registry/certs/package-registry.crt -subj "/CN=$(curl -s ifconfig.me)" -days 3650

#   - docker pull docker.elastic.co/package-registry/package-registry:main
#   - docker run -d --name package-registry --restart always -p 443:8443 -v /etc/package-registry/packages:/packages/package-registry:ro -v /etc/package-registry/certs:/etc/package-registry/certs:ro docker.elastic.co/package-registry/package-registry:main --address=0.0.0.0:8443 --tls-key=/etc/package-registry/certs/package-registry.key --tls-cert=/etc/package-registry/certs/package-registry.crt
# YAML

# buildkite-agent artifact upload cloud-init.yaml


# # Trigger the OOM testing pipeline
# cat <<YAML | buildkite-agent pipeline upload
# steps:
#   - key: 'deploy-epr-instance-$BUILDKITE_BUILD_NUMBER'
#     label: ':package::sparkles: [security_detection_engine] Deploying EPR instance'
#     agents:
#       provider: gcp
#       image: ${IMAGE_UBUNTU_X86_64}
#     plugins:
#         - elastic/oblt-google-auth#v1.3.0:
#             lifetime: 10800 # seconds
#             project-id: "elastic-kibana-184716"
#             project-number: "261553193300"
#     commands:
#       - buildkite-agent artifact download cloud-init.yaml .
#       - |
#         gcloud compute instances create "$EPR_INSTANCE_NAME" \
#         --zone="$GCP_ZONE" \
#         --machine-type=e2-micro \
#         --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default \
#         --provisioning-model=STANDARD \
#         --tags=https-server \
#         --create-disk=auto-delete=yes,boot=yes,device-name="$EPR_INSTANCE_NAME",image=projects/cos-cloud/global/images/cos-109-17800-570-50,mode=rw,size=10,type=pd-standard \
#         --labels=goog-ec-src=vm_add-gcloud \
#         --reservation-affinity=any \
#         --metadata-from-file=user-data=cloud-init.yaml \
#         --quiet
#       - (cd ./packages && zip -r ../security_detection_engine.zip ./security_detection_engine)
#       - while :; do sleep 1m && gcloud compute scp --recurse ./security_detection_engine.zip maxim_palenov@maximpn-epr-docker:/etc/package-registry/packages/ --zone "$GCP_ZONE" done
#       - buildkite-agent env set EC_PLAN_PROP_FLEET_REGISTRY_URL \$(gcloud compute instances describe "$EPR_INSTANCE_NAME" --zone="$GCP_ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
#   - key: 'run-oom-testing-$BUILDKITE_BUILD_NUMBER'
#     label: ":bar_chart: [security_detection_engine] Trigger OOM testing pipeline"
#     depends_on:
#       - step: 'deploy-epr-instance-$BUILDKITE_BUILD_NUMBER'
#         allow_failure: false
#     trigger: "appex-qa-stateful-security-prebuilt-rules-ftr-oom-testing"
#     async: false
#     build:
#       env:
#         EC_PLAN_PROP_FLEET_REGISTRY_URL: unknown
#         EC_PLAN_PROP_PREBUILT_RULES_PACKAGE_VERSION: "$PACKAGE_VERSION"
#   - key: 'remove-epr-instance-$BUILDKITE_BUILD_NUMBER'
#     label: ":broom::sparkles: [security_detection_engine] Removing EPR instance"
#     depends_on:
#       - step: 'run-oom-testing-$BUILDKITE_BUILD_NUMBER'
#         allow_failure: true
#     agents:
#       provider: gcp
#       image: ${IMAGE_UBUNTU_X86_64}
#     plugins:
#     - elastic/oblt-google-auth#v1.3.0:
#         lifetime: 10800 # seconds
#         project-id: "elastic-kibana-184716"
#         project-number: "261553193300"
#     command: |
#       gcloud compute instances delete $EPR_INSTANCE_NAME --zone=us-west2-a --delete-disks=all --quiet
# YAML

# echo "--- :broom::sparkles: Remove EPR instance: $EPR_INSTANCE_NAME (Mock)"
# gcloud compute instances delete $EPR_INSTANCE_NAME --zone=us-west2-a --delete-disks=all --quiet