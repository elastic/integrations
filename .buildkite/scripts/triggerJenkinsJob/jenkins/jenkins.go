// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package jenkins

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/bndr/gojenkins"
)

type JenkinsClient struct {
	client *gojenkins.Jenkins
}

type Options struct {
	WaitingTime    time.Duration
	MaxWaitingTime time.Duration
	GrowthFactor   float64
	Retries        int
}

func NewJenkinsClient(ctx context.Context, host, user, token string) (*JenkinsClient, error) {
	jenkins, err := gojenkins.CreateJenkins(nil, host, user, token).Init(ctx)
	if err != nil {
		return nil, fmt.Errorf("client coult not be created: %w", err)
	}

	return &JenkinsClient{
		client: jenkins,
	}, nil
}

func (j *JenkinsClient) RunJob(ctx context.Context, jobName string, async bool, params map[string]string, opts Options) error {
	log.Printf("Building job %s", jobName)
	var queueId int64

	r := retry(func(ctx context.Context) error {
		var err error
		queueId, err = j.client.BuildJob(ctx, jobName, params)
		if err != nil {
			return fmt.Errorf("error running job %s: %w", jobName, err)
		}

		if queueId != 0 {
			return nil
		}
		return fmt.Errorf("already running %s?", jobName)

	}, opts.Retries, opts.GrowthFactor, opts.WaitingTime, opts.MaxWaitingTime)

	if err := r(ctx); err != nil {
		return err
	}

	build, err := j.getBuildFromJobAndQueueID(ctx, jobName, queueId)
	if err != nil {
		return err
	}
	log.Printf("Job triggered %s/%d\n", jobName, build.GetBuildNumber())

	if async {
		return nil
	}

	log.Printf("Waiting to be finished %s\n", build.GetUrl())
	err = j.waitForBuildFinished(ctx, build)
	if err != nil {
		return fmt.Errorf("not finished job %s/%d: %w", jobName, build.GetBuildNumber(), err)
	}

	log.Printf("Build %s finished with result: %s\n", build.GetUrl(), build.GetResult())

	if build.GetResult() != gojenkins.STATUS_SUCCESS {
		return fmt.Errorf("build %s finished with result %s", build.GetUrl(), build.GetResult())
	}
	return nil
}

func (j *JenkinsClient) getBuildFromJobAndQueueID(ctx context.Context, jobName string, queueId int64) (*gojenkins.Build, error) {
	job, err := j.client.GetJob(ctx, jobName)
	if err != nil {
		return nil, fmt.Errorf("not able to get job %s: %w", jobName, err)
	}

	build, err := j.getBuildFromQueueID(ctx, job, queueId)
	if err != nil {
		return nil, fmt.Errorf("not able to get build from %s: %w", jobName, err)
	}
	return build, nil
}

// based on https://github.com/bndr/gojenkins/blob/master/jenkins.go#L282
func (j *JenkinsClient) getBuildFromQueueID(ctx context.Context, job *gojenkins.Job, queueid int64) (*gojenkins.Build, error) {
	task, err := j.client.GetQueueItem(ctx, queueid)
	if err != nil {
		return nil, err
	}
	// Jenkins queue API has about 4.7second quiet period
	for task.Raw.Executable.Number == 0 {
		select {
		case <-time.After(1000 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		_, err = task.Poll(ctx)
		if err != nil {
			return nil, err
		}
	}

	build, err := job.GetBuild(ctx, task.Raw.Executable.Number)
	if err != nil {
		return nil, fmt.Errorf("not able to retrieve build %s", task.Raw.Executable.Number, err)
	}
	return build, nil
}

func (j *JenkinsClient) waitForBuildFinished(ctx context.Context, build *gojenkins.Build) error {
	const waitingPeriod = 10000 * time.Millisecond
	for build.IsRunning(ctx) {
		log.Printf("Build still running, waiting for %s...", waitingPeriod)
		select {
		case <-time.After(waitingPeriod):
		case <-ctx.Done():
			return ctx.Err()
		}
		_, err := build.Poll(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}
