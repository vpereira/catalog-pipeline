# Pipeline Project

## Project Structure

```
.
├── go.mod
├── http-server-test
│   └── main.go
└── pipeline
    └── main.go
```

## Description

This project consists of two main components:

1. **HTTP Server Test**: A simple HTTP server simulating the catalog.
2. **Pipeline**: A pipeline that processes Docker images using \`skopeo\` and \`trivy\`. Pushing results to the catalog

## Usage

### Running the HTTP Server

First, start the HTTP server which simulates the catalog:

```
go run http-server-test/main.go
```

### Running the Pipeline

Next, run the pipeline:

```
go run pipeline/main.go
```

## Pipeline Functionality

The pipeline performs the following tasks:

1. Uses \`skopeo\` to find the supported architectures for the given Docker image.
2. Downloads the tar files for each architecture.
3. Calculates the size of each downloaded image and submits the data to the catalog.
4. Generates a \`trivy\` report (only for the default architecture) and submits the report to the catalog in parallel with the size data submission.

### Note

In a real-world scenario, the images are sourced from Redis.

