// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/trigger-jenkins-buildkite-plugin/jenkins"
)

const (
	publishingRemoteJob = "package_storage/job/publishing-job-remote"
	signingJob          = "elastic+unified-release+master+sign-artifacts-with-gpg"

	publishJobKey = "publish"
	signJobKey    = "sign"
)

var allowedJenkinsJobs = map[string]string{
	publishJobKey: publishingRemoteJob,
	signJobKey:    signingJob,
}

var (
	jenkinsHost  = os.Getenv("JENKINS_HOST_SECRET")
	jenkinsUser  = os.Getenv("JENKINS_USERNAME_SECRET")
	jenkinsToken = os.Getenv("JENKINS_TOKEN")
)

func jenkinsJobOptions() []string {
	keys := make([]string, 0, len(allowedJenkinsJobs))
	for k := range allowedJenkinsJobs {
		keys = append(keys, k)
	}
	return keys
}

func main() {
	jenkinsJob := flag.String("jenkins-job", "", fmt.Sprintf("Jenkins job to trigger. Allowed values: %s", strings.Join(jenkinsJobOptions(), " ,")))
	waitingTime := flag.Duration("waiting-time", 5*time.Second, "Waiting period between each retry")
	growthFactor := flag.Float64("growth-factor", 1.25, "Growth-Factor used for exponential backoff delays")
	retries := flag.Int("retries", 20, "Number of retries to trigger the job")
	maxWaitingTime := flag.Duration("max-waiting-time", 60*time.Minute, "Maximum waiting time per each retry")

	folderPath := flag.String("folder", "", "Path to artifacts folder")
	zipPackagePath := flag.String("package", "", "Path to zip package file (*.zip)")
	sigPackagePath := flag.String("signature", "", "Path to the signature file of the package file (*.zip.sig)")
	async := flag.Bool("async", false, "Run async the Jenkins job")
	dryRun := flag.Bool("dry-run", true, "Trigger in DRY_RUN mode the pipeline")
	legacyPackage := flag.Bool("legacy-package", false, "Legacy package, spec validation will be disabled")
	flag.Parse()

	if _, ok := allowedJenkinsJobs[*jenkinsJob]; !ok {
		log.Fatal("Invalid jenkins job")
	}

	log.Printf("Triggering job: %s", allowedJenkinsJobs[*jenkinsJob])

	ctx := context.Background()
	client, err := jenkins.NewJenkinsClient(ctx, jenkinsHost, jenkinsUser, jenkinsToken)
	if err != nil {
		log.Fatalf("error creating jenkins client")
	}

	opts := jenkins.Options{
		WaitingTime:    *waitingTime,
		Retries:        *retries,
		GrowthFactor:   *growthFactor,
		MaxWaitingTime: *maxWaitingTime,
	}

	switch *jenkinsJob {
	case publishJobKey:
		err = runPublishingRemoteJob(ctx, client, *async, allowedJenkinsJobs[*jenkinsJob], *zipPackagePath, *sigPackagePath, *dryRun, *legacyPackage, opts)
	case signJobKey:
		err = runSignPackageJob(ctx, client, *async, allowedJenkinsJobs[*jenkinsJob], *folderPath, opts)
	default:
		log.Fatal("unsupported jenkins job")
	}

	if err != nil {
		log.Fatalf("Error: %s", err)
	}
}

func runSignPackageJob(ctx context.Context, client *jenkins.JenkinsClient, async bool, jobName, folderPath string, opts jenkins.Options) error {
	if folderPath == "" {
		return fmt.Errorf("missing parameter --gcs_input_path for")
	}
	params := map[string]string{
		"gcs_input_path": folderPath,
	}

	return client.RunJob(ctx, jobName, async, params, opts)
}

func runPublishingRemoteJob(ctx context.Context, client *jenkins.JenkinsClient, async bool, jobName, packagePath, signaturePath string, dryRun, legacyPackage bool, opts jenkins.Options) error {
	if packagePath == "" {
		return fmt.Errorf("missing parameter --gs_package_build_zip_path")
	}
	if signaturePath == "" {
		return fmt.Errorf("missing parameter --gs_package_signature_path")
	}

	// Run the job with some parameters
	params := map[string]string{
		"dry_run":                   strconv.FormatBool(dryRun),
		"gs_package_build_zip_path": packagePath,
		"gs_package_signature_path": signaturePath,
		"legacy_package":            strconv.FormatBool(legacyPackage),
	}

	return client.RunJob(ctx, jobName, async, params, opts)
}
