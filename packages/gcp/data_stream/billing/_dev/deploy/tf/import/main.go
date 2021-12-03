package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/bigquery"
)

func importFromFile(projectID, datasetID, tableID, schemaFile, filename string) error {
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("bigquery.NewClient: %v", err)
	}
	defer client.Close()

	schemaData, err := os.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("cannot read schema file: %w", err)
	}

	schema, err := bigquery.SchemaFromJSON(schemaData)
	if err != nil {
		return fmt.Errorf("cannot parse schema from JSON: %w", err)
	}

	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("cannot open data file: %w", err)
	}

	// create a reader source with schema autodetection and correct format
	// (required for schema autodetection to work)
	source := bigquery.NewReaderSource(f)
	source.Schema = schema
	source.SourceFormat = bigquery.JSON

	// create a loader that truncates the table, so only the data in the
	// test file are present after import process
	loader := client.Dataset(datasetID).Table(tableID).LoaderFrom(source)
	loader.WriteDisposition = bigquery.WriteEmpty

	job, err := loader.Run(ctx)
	if err != nil {
		return fmt.Errorf("loader run failed: %w", err)
	}

	status, err := job.Wait(ctx)
	if err != nil {
		return fmt.Errorf("waiting job completion failed: %w", err)
	}

	if err := status.Err(); err != nil {
		for _, e := range status.Errors {
			fmt.Println(e.Message)
		}
		return fmt.Errorf("job completed with failure: %w", err)
	}
	return nil
}

var projectID = flag.String("project-id", "", "")
var datasetID = flag.String("dataset-id", "", "")
var tableID = flag.String("table-id", "", "")
var schemaFile = flag.String("schema-file", "", "")
var filename = flag.String("filename", "", "")

func main() {
	flag.Parse()

	fmt.Printf("Will load JSON data from %s and upload to id=projects/%s/datasets/%s/tables/%s\n", *filename, *projectID, *datasetID, *tableID)

	err := importFromFile(*projectID, *datasetID, *tableID, *schemaFile, *filename)
	if err != nil {
		log.Fatal(fmt.Errorf("data upload failed: %w", err))
	}
}
