# GCS Setup

provider "google" {
  default_labels = {
  gcs_environment  = var.ENVIRONMENT
  gcs_repo         = var.REPO
  gcs_branch       = var.BRANCH
  gcs_build        = var.BUILD_ID
  gcs_created_date = var.CREATED_DATE
  }
}

resource "google_storage_bucket" "netskope_event_bucket" {
  name     = "elastic-package-gcs-bucket-${var.TEST_RUN_ID}"
  location = var.BUCKET_REGION
}
# See https://github.com/elastic/oblt-infra/blob/main/conf/resources/repos/integrations/01-gcp-buildkite-oidc.tf

resource "google_storage_bucket_object" "netskope_event_bucket_object" {
  name   = var.OBJECT_NAME
  bucket = google_storage_bucket.netskope_event_bucket.name
  source = var.FILE_PATH
}

output "netskope_event_bucket_name" {
  value = google_storage_bucket.netskope_event_bucket.name
}

# AWS Setup

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      aws_environment  = var.ENVIRONMENT
      aws_repo         = var.REPO
      aws_branch       = var.BRANCH
      aws_build        = var.BUILD_ID
      aws_created_date = var.CREATED_DATE
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
  key    = "events.csv.gz"
  content_base64   = base64gzip(file("./files/events.csv"))
  content_encoding = "gzip"
  content_type     = "text/csv"

  depends_on = [aws_sqs_queue.queue]
}

output "queue_url" {
  value = aws_sqs_queue.queue.url
}
