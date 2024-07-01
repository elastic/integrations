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

resource "aws_s3_bucket" "cisco_umbrella" {
  bucket = "elastic-package-cisco-umbrella-bucket-${var.TEST_RUN_ID}"
}

resource "aws_s3_object" "cisco_umbrella_auditlogs" {
  bucket = aws_s3_bucket.cisco_umbrella.id
  key    = "auditlogs.log"
  source = "./files/test-umbrella-auditlogs.log"
  depends_on = [aws_sqs_queue.cisco_umbrella_queue]
}

resource "aws_s3_object" "cisco_umbrella_dnslogs" {
  bucket = aws_s3_bucket.cisco_umbrella.id
  key    = "dnslogs.log"
  source = "./files/test-umbrella-dnslogs.log"
  depends_on = [aws_sqs_queue.cisco_umbrella_queue]
}

resource "aws_s3_object" "cisco_umbrella_firewalllogs" {
  bucket = aws_s3_bucket.cisco_umbrella.id
  key    = "firewalllogs.log"
  source = "./files/test-umbrella-firewalllogs.log"
  depends_on = [aws_sqs_queue.cisco_umbrella_queue]
}

resource "aws_s3_object" "cisco_umbrella_intrusionlogs" {
  bucket = aws_s3_bucket.cisco_umbrella.id
  key    = "intrusionlogs.log"
  source = "./files/test-umbrella-intrusionlogs.log"
  depends_on = [aws_sqs_queue.cisco_umbrella_queue]
}

resource "aws_s3_object" "cisco_umbrella_proxylogs" {
  bucket = aws_s3_bucket.cisco_umbrella.id
  key    = "proxylogs.log"
  source = "./files/test-umbrella-proxylogs.log"
  depends_on = [aws_sqs_queue.cisco_umbrella_queue]
}

resource "aws_sqs_queue" "cisco_umbrella_queue" {
  name       = "elastic-package-cisco-umbrella-queue-${var.TEST_RUN_ID}"
  policy     = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:*:elastic-package-cisco-umbrella-queue-${var.TEST_RUN_ID}",
      "Condition": {
        "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.cisco_umbrella.arn}" }
      }
    }
  ]
}
EOF
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.cisco_umbrella.id

  queue {
    queue_arn = aws_sqs_queue.cisco_umbrella_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}
