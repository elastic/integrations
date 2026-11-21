provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      environment  = var.ENVIRONMENT
      repo         = var.REPO
      branch       = var.BRANCH
      build        = var.BUILD_ID
      created_date = var.CREATED_DATE

      division = "engineering"
      org      = "obs"
      team     = "security-service-integrations" # owner.github in manifest.yml
      project  = "integrations-datadog-package"  # name in manifest.yml
    }
  }
}

locals {
  # Datadog Log Archives writes gzipped NDJSON into a date-partitioned layout
  # under the archive root: <root>/dt=<YYYYMMDD>/hour=<HH>/<archive-id>.json.gz
  archive_root = "datadog-audit"
  archive_key  = "${local.archive_root}/dt=20260731/hour=19/archive_192315.0000000000000001.json.gz"
}

resource "aws_s3_bucket" "datadog" {
  bucket        = "elastic-package-datadog-audit-bucket-${var.TEST_RUN_ID}"
  force_destroy = true
}

resource "aws_sqs_queue" "datadog" {
  name   = "elastic-package-datadog-audit-queue-${var.TEST_RUN_ID}"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-datadog-audit-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.datadog.arn}" }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_notification" "datadog" {
  bucket = aws_s3_bucket.datadog.id

  queue {
    queue_arn = aws_sqs_queue.datadog.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_object" "archive" {
  bucket = aws_s3_bucket.datadog.id
  key    = local.archive_key

  # The fixture is committed as uncompressed NDJSON (as .log, the extension the
  # package spec permits in this folder) so it stays reviewable in diffs; gzip
  # it here so the uploaded object matches what Log Archives actually delivers
  # and the package's default `.*\.json\.gz$` file selector runs as shipped.
  content_base64 = base64gzip(file("${path.module}/files/test-audit.log"))

  # Deliberately not application/json or application/x-ndjson: those content
  # types make the aws-s3 input decode the object with its own JSON reader.
  # Leaving it as gzip keeps the plain line reader, so each NDJSON line arrives
  # as one `message` — the shape data_stream/audit's ingest pipeline parses.
  content_type = "application/gzip"

  # Object creation must follow the notification config, otherwise the
  # s3:ObjectCreated event is never delivered to the queue.
  depends_on = [aws_s3_bucket_notification.datadog]
}

output "queue_url" {
  value = aws_sqs_queue.datadog.url
}

output "bucket_arn" {
  value = aws_s3_bucket.datadog.arn
}

output "bucket_list_prefix" {
  value = "${local.archive_root}/"
}
