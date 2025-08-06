# GCS Setup

provider "google" {
  default_labels = {
  environment  = var.ENVIRONMENT
  repo         = var.REPO
  branch       = var.BRANCH
  build        = var.BUILD_ID
  created_date = var.CREATED_DATE
  }
}

resource "google_storage_bucket" "netskope_transaction_bucket" {
  name     = "elastic-package-gcs-bucket-${var.TEST_RUN_ID}"
  location = var.BUCKET_REGION
}
# See https://github.com/elastic/oblt-infra/blob/main/conf/resources/repos/integrations/01-gcp-buildkite-oidc.tf

resource "google_storage_bucket_object" "netskope_transaction_bucket_object" {
  name   = var.OBJECT_NAME
  bucket = google_storage_bucket.netskope_transaction_bucket.name
  source = var.FILE_PATH
}

output "netskope_transaction_bucket_name" {
  value = google_storage_bucket.netskope_transaction_bucket.name
}

# AWS Setup

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      environment  = var.ENVIRONMENT
      repo         = var.REPO
      branch       = var.BRANCH
      build        = var.BUILD_ID
      created_date = var.CREATED_DATE
    }
  }
}

resource "aws_s3_bucket" "bucket" {
  bucket = "elastic-package-netskope-bucket-${var.TEST_RUN_ID}"
}

resource "aws_sqs_queue" "queue" {
  name       = "elastic-package-netskope-queue-${var.TEST_RUN_ID}"
  policy     = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-netskope-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.bucket.arn}" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.bucket.id

  queue {
    queue_arn = aws_sqs_queue.queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_object" "object" {
  bucket = aws_s3_bucket.bucket.id
  key    = "trxn.csv.gz"
  content_base64   = base64gzip(file("./files/trxn.csv"))
  content_encoding = "gzip"
  content_type     = "text/csv"

  depends_on = [aws_sqs_queue.queue]
}

output "queue_url" {
  value = aws_sqs_queue.queue.url
}
