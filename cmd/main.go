package main

import (
	"context"
	"flag"
	"log"

	"cloud.google.com/go/storage"
	"github.com/kubermatic/tail/pkg/handler"
)

var (
	bucketName, cacheDir, listenPort, clientID, clientSecret string
)

func main() {
	flag.StringVar(&bucketName, "bucket-name", "prow-data", "Name of the bucket")
	flag.StringVar(&cacheDir, "cache-dir", "./", "The directory to use for caching")
	flag.StringVar(&listenPort, "listen-port", ":5000", "Port to listen on")
	flag.StringVar(&clientID, "client-id", "", "Google Client ID")
	flag.StringVar(&clientSecret, "client-secret", "", "Google Client Secret")
	flag.Parse()

	if len(clientID) == 0 {
		log.Fatalf("client-id cannot be empty")
	}
	if len(clientSecret) == 0 {
		log.Fatalf("client-secret cannot be empty")
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create storage client: %v", err)
	}

	bkt := client.Bucket(bucketName)
	server := handler.New(bkt, cacheDir, listenPort, clientID, clientSecret)

	log.Printf("Starting to listen on %s", listenPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
}
