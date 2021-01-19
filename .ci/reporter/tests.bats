#!/usr/bin/env bats

load test_helpers

IMAGE="integrations/test-reporter"

@test "Build image" {
	run docker build . -t $IMAGE
    [ "$status" -eq 0 ]
}