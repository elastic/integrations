variable "TEST_RUN_ID" {
  default = "detached"
}

provider "aws" {
  default_tags {
    tags = {
      environment  = var.ENVIRONMENT
      repo         = var.REPO
      branch       = var.BRANCH
      build        = var.BUILD_ID
      created_date = var.CREATED_DATE

      division = "engineering"
      org      = "obs"
      team     = "security-service-integrations"
      project  = "integrations-aws-package"
    }
  }
}

# The bucket name prefix must stay at or under 26 characters. TEST_RUN_ID is a
# 36-character UUID and the S3 bucket name limit is 63.
resource "aws_s3_bucket" "bucket" {
  bucket        = "elastic-package-aws-bench-${var.TEST_RUN_ID}"
  force_destroy = true
}

resource "aws_sqs_queue" "queue" {
  name   = "elastic-package-aws-bench-queue-${var.TEST_RUN_ID}"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-aws-bench-queue-${var.TEST_RUN_ID}",
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

# The NDJSON file here is generated in advance by the corpus generator
# (cloudtrail-benchmark/template.ndjson) using
# elastic-integration-corpus-generator-tool. Using this static file is a
# workaround required due to current elastic-package limitations outlined at:
# https://github.com/elastic/elastic-package/issues/3452
#
# The object key MUST contain "/CloudTrail/" so it matches a file_selectors entry
# rendered by data_stream/cloudtrail/agent/stream/aws-s3.yml.hbs. A key matching no
# selector is silently skipped and the benchmark reports zero documents. The key
# shape below mirrors a real CloudTrail delivery path.
#
# files/cloudtrail-corpus.log is newline-delimited JSON -- one bare CloudTrail event
# per line, NOT a {"Records":[...]} wrapper. The input reads these objects line by
# line and `expand_event_list_from_field: Records` was observed not to fire, so a
# Records-wrapped file is ingested as one opaque document per object instead of one
# document per event. Keep one event per line.
#
# The .log extension matches the repo convention for newline-delimited fixtures and
# keeps editors from validating the file as a single JSON document.
#
# depends_on is required: objects created before the notification exists produce no
# SQS message, so the agent never learns about them.
resource "aws_s3_object" "corpus" {
  count = var.object_count

  bucket = aws_s3_bucket.bucket.id
  key = format(
    "AWSLogs/123456789012/CloudTrail/us-east-1/2026/07/26/123456789012_CloudTrail_us-east-1_20260726T2350Z_%05d.json",
    count.index,
  )
  source = "${path.module}/files/cloudtrail-corpus.log"

  depends_on = [aws_s3_bucket_notification.bucket_notification]
}

output "queue_url" {
  value = aws_sqs_queue.queue.url
}
