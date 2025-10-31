#!/bin/bash

set -euo pipefail

PACKAGE_VERSION=$(yq -r '.version' ./packages/security_detection_engine/manifest.yml)
EPR_INSTANCE_NAME="bk-epr-prebuilt-rules-oom-testing-$BUILDKITE_BUILD_NUMBER"
EPR_VM_IMAGE="projects/elastic-kibana-184716/global/images/rule-management-epr-oct-28"

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

# Upload the tested package

# Trigger the OOM testing pipeline
cat <<YAML | buildkite-agent pipeline upload
steps:
  - key: 'deploy-epr-instance-$BUILDKITE_BUILD_NUMBER'
    label: ':package::sparkles: [security_detection_engine] Deploying EPR instance'
    agents:
      provider: gcp
      image: ${IMAGE_UBUNTU_X86_64}
    command: |
      gcloud compute instances create "$EPR_INSTANCE_NAME" \
      --zone=us-west2-a \
      --machine-type=e2-small \
      --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default \
      --provisioning-model=STANDARD \
      --tags=https-server \
      --create-disk=auto-delete=yes,boot=yes,device-name=instance-20251031-131502,image="$EPR_VM_IMAGE",mode=rw,size=10,type=pd-standard \
      --no-shielded-secure-boot \
      --no-shielded-vtpm \
      --no-shielded-integrity-monitoring \
      --labels=goog-ec-src=vm_add-gcloud \
      --reservation-affinity=any
      --quiet
  - key: 'run-oom-testing-$BUILDKITE_BUILD_NUMBER'
    label: ":bar_chart: [security_detection_engine] Trigger OOM testing pipeline"
    depends_on:
      - step: 'deploy-epr-instance-$BUILDKITE_BUILD_NUMBER'
        allow_failure: false
    trigger: "appex-qa-stateful-security-prebuilt-rules-ftr-oom-testing"
    async: false
    build:
      env:
        EC_PLAN_PROP_FLEET_REGISTRY_URL: unknown
        EC_PLAN_PROP_PREBUILT_RULES_PACKAGE_VERSION: unknown
  - key: 'remove-epr-instance-$BUILDKITE_BUILD_NUMBER'
    label: ":broom::sparkles: [security_detection_engine] Removing EPR instance"
    depends_on:
      - step: 'run-oom-testing-$BUILDKITE_BUILD_NUMBER'
        allow_failure: true
    agents:
      provider: gcp
      image: ${IMAGE_UBUNTU_X86_64}
    command: |
      gcloud compute instances delete $EPR_INSTANCE_NAME --zone=us-west2-a --delete-disks=all --quiet
YAML

# echo "--- :broom::sparkles: Remove EPR instance: $EPR_INSTANCE_NAME (Mock)"
# gcloud compute instances delete $EPR_INSTANCE_NAME --zone=us-west2-a --delete-disks=all --quiet