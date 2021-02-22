// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bufio"
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/iterator"
)

const (
	emulatorProjectID = "system-tests"
)

var logger = log.New(os.Stdout, "", log.LstdFlags)

func main() {
	// Create pubsub client for setting up and communicating to emulator.
	client, clientCancel := setup()
	defer clientCancel()
	defer client.Close()

	for _, topic := range []string{"audit", "firewall", "vpcflow"} {
		createTopic(topic, client)
		createSubscription(topic+"-sub", topic, client)
		publishMessages(topic, client)
	}
}

func setup() (*pubsub.Client, context.CancelFunc) {
	const host = "0.0.0.0:8432"

	os.Setenv("PUBSUB_EMULATOR_HOST", host)

	httpClient := http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	var resp *http.Response
	var err error
	for {
		// Sanity check the emulator.
		resp, err = httpClient.Get("http://" + host)
		if err != nil {
			logger.Printf("pubsub emulator at %s is not healthy yet: %v\n", host, err)
			time.Sleep(time.Second)
			continue
		}
		defer resp.Body.Close()
		break
	}

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Fatal("failed to read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.Fatalf("pubsub emulator is not healthy, got status code %d", resp.StatusCode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	client, err := pubsub.NewClient(ctx, emulatorProjectID)
	if err != nil {
		logger.Fatalf("failed to create client: %v", err)
	}

	resetPubSub(client)
	return client, cancel
}

func resetPubSub(client *pubsub.Client) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Clear topics.
	topics := client.Topics(ctx)
	for {
		topic, err := topics.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			logger.Fatal(err)
		}
		if err = topic.Delete(ctx); err != nil {
			logger.Fatalf("failed to delete topic %v: %v", topic.ID(), err)
		}
	}

	// Clear subscriptions.
	subs := client.Subscriptions(ctx)
	for {
		sub, err := subs.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			logger.Fatal(err)
		}

		if err = sub.Delete(ctx); err != nil {
			logger.Fatalf("failed to delete subscription %v: %v", sub.ID(), err)
		}
	}
}

func createTopic(emulatorTopic string, client *pubsub.Client) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	topic := client.Topic(emulatorTopic)
	exists, err := topic.Exists(ctx)
	if err != nil {
		logger.Fatalf("failed to check if topic exists: %v", err)
	}
	if !exists {
		if topic, err = client.CreateTopic(ctx, emulatorTopic); err != nil {
			logger.Fatalf("failed to create the topic: %v", err)
		}
		logger.Println("Topic created:", topic.ID())
	}
}

func publishMessages(emulatorTopic string, client *pubsub.Client) []string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	topic := client.Topic(emulatorTopic)
	defer topic.Stop()

	file, err := os.Open("/sample_logs/" + emulatorTopic + ".log")
	if err != nil {
		logger.Fatal(err)
	}
	defer file.Close()

	var messageIDs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		result := topic.Publish(ctx, &pubsub.Message{
			Data: scanner.Bytes(),
		})

		// Wait for message to publish and get assigned ID.
		id, err := result.Get(ctx)
		if err != nil {
			logger.Fatal(err)
		}
		messageIDs = append(messageIDs, id)
	}

	if err := scanner.Err(); err != nil {
		logger.Fatal(err)
	}

	logger.Printf("Published %d messages to topic %v. ID range: [%v, %v]", len(messageIDs), topic.ID(), messageIDs[0], messageIDs[len(messageIDs)-1])
	return messageIDs
}

func createSubscription(emulatorSubscription, emulatorTopic string, client *pubsub.Client) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := client.Subscription(emulatorSubscription)
	exists, err := sub.Exists(ctx)
	if err != nil {
		logger.Fatalf("failed to check if sub exists: %v", err)
	}
	if exists {
		return
	}

	sub, err = client.CreateSubscription(ctx, emulatorSubscription, pubsub.SubscriptionConfig{
		Topic: client.Topic(emulatorTopic),
	})
	if err != nil {
		logger.Fatalf("failed to create subscription: %v", err)
	}
	logger.Println("New subscription created:", sub.ID())
}
