package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	var nc *nats.Conn
	var err error

	// Wait for NATS to become ready
	for i := 0; i < 30; i++ {
		nc, err = nats.Connect("nats://127.0.0.1:4222")
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	var js jetstream.JetStream
	js, err = jetstream.New(nc)
	if err != nil {
		log.Fatalf("Failed to create JetStream context: %v", err)
	}

	cfg := jetstream.StreamConfig{
		Name:        "ORDERS",
		Description: "Orders stream for system testing",
		Subjects:    []string{"orders.*"},
		Storage:     jetstream.FileStorage,
		Retention:   jetstream.LimitsPolicy,
		MaxMsgs:     10000,
		MaxBytes:    10485760,
		MaxAge:      24 * time.Hour,
		MaxMsgSize:  1048576,
		Replicas:    1,
	}

	var stream jetstream.Stream
	for i := 0; i < 30; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err = js.CreateOrUpdateStream(ctx, cfg)
		cancel()
		if err == nil {
			fmt.Printf("Stream created: %s\n", stream.CachedInfo().Config.Name)
			break
		}
		log.Printf("CreateOrUpdateStream attempt %d failed: %v, retrying...", i+1, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to create stream after retries: %v", err)
	}

	consumerCfg := jetstream.ConsumerConfig{
		Name:          "PROCESSOR",
		Durable:       "PROCESSOR",
		Description:   "Order processor consumer",
		DeliverPolicy: jetstream.DeliverAllPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    5,
		FilterSubject: "orders.*",
		ReplayPolicy:  jetstream.ReplayInstantPolicy,
		MaxAckPending: 1000,
	}

	var consumer jetstream.Consumer
	for i := 0; i < 30; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		consumer, err = js.CreateOrUpdateConsumer(ctx, "ORDERS", consumerCfg)
		cancel()
		if err == nil {
			fmt.Printf("Consumer created: %s\n", consumer.CachedInfo().Config.Name)
			break
		}
		log.Printf("CreateOrUpdateConsumer attempt %d failed: %v, retrying...", i+1, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to create consumer after retries: %v", err)
	}

	// Initial batch of messages
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		msg := fmt.Sprintf("order data %d", i)
		if _, err := js.Publish(ctx, "orders.created", []byte(msg)); err != nil {
			log.Printf("Initial publish error for message %d: %v", i, err)
		}
		cancel()
	}

	// Continuous loop
	ticker := time.NewTicker(200 * time.Millisecond)
	count := 20
	for range ticker.C {
		count++
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		msg := fmt.Sprintf("order data %d", count)
		_, err := js.Publish(ctx, "orders.created", []byte(msg))
		cancel()
		if err != nil {
			log.Printf("Publish error: %v", err)
			continue
		}

		if count%2 == 0 && consumer != nil {
			msgs, err := consumer.Fetch(1, jetstream.FetchMaxWait(50*time.Millisecond))
			if err == nil {
				for m := range msgs.Messages() {
					_ = m.Ack()
				}
			}
		}
	}
}
