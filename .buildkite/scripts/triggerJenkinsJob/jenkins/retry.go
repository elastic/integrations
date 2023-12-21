// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package jenkins

import (
	"context"
	"log"
	"math"
	"time"
)

type retryableFunction func(context.Context) error

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func retry(f retryableFunction, retries int, growthFactor float64, delay, maxDelay time.Duration) retryableFunction {
	return func(ctx context.Context) error {
		delaySeconds := delay.Seconds()
		for r := 0; ; r++ {
			err := f(ctx)
			if err == nil || r >= retries {
				// Return when there is no error or the maximum amount
				// of retries is reached.
				return err
			}

			waitingTimeSeconds := math.Pow(growthFactor, float64(r)) * delaySeconds
			waitingTime := time.Duration(waitingTimeSeconds) * time.Second
			waitingTime = minDuration(waitingTime, maxDelay)

			log.Printf("Function failed, retrying in %v -> %.2f", waitingTime, waitingTimeSeconds)

			select {
			case <-time.After(waitingTime):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
}
