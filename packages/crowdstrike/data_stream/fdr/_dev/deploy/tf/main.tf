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
    }
  }
}

output "queue_url" {
  value = aws_sqs_queue.crowdstrike_queue.url
}

# Common queue
resource "aws_sqs_queue" "crowdstrike_queue" {
  name       = "elastic-package-crowdstrike-queue-${var.TEST_RUN_ID}"
  policy     = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-crowdstrike-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.crowdstrike_data_bucket.arn}" }
      }
    },
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-crowdstrike-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.crowdstrike_aidmaster_bucket.arn}" }
      }
    }
  ]
}
POLICY
}

# Log data for events
resource "aws_s3_bucket_notification" "crowdstrike_data_bucket_notification" {
  bucket = aws_s3_bucket.crowdstrike_data_bucket.id

  queue {
    queue_arn = aws_sqs_queue.crowdstrike_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}
resource "aws_s3_bucket" "crowdstrike_data_bucket" {
  bucket = "elastic-package-crowdstrike-data-bucket-${var.TEST_RUN_ID}"
}
resource "aws_s3_object" "crowdstrike_data" {
  bucket = aws_s3_bucket.crowdstrike_data_bucket.id
  key    = "data"
  source = "./files/fdr-sample.log"
  depends_on = [aws_sqs_queue.crowdstrike_queue]
}

# Host info for enrichment
resource "aws_s3_bucket_notification" "crowdstrike_aidmaster_bucket_notification" {
  bucket = aws_s3_bucket.crowdstrike_aidmaster_bucket.id

  queue {
    queue_arn = aws_sqs_queue.crowdstrike_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}
resource "aws_s3_bucket" "crowdstrike_aidmaster_bucket" {
  bucket = "elastic-package-crowdstrike-aidmaster-bucket-${var.TEST_RUN_ID}"
}
resource "aws_s3_object" "crowdstrike_aidmaster" {
  bucket = aws_s3_bucket.crowdstrike_aidmaster_bucket.id
  key    = "fdrv2/aidmaster"
  source = "./files/fdr-0_aidmaster.log"
  depends_on = [aws_sqs_queue.crowdstrike_queue]
}
