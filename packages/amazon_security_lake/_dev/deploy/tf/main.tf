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

resource "aws_s3_bucket" "bucket" {
  bucket = "elastic-package-security-lake-bucket-${var.TEST_RUN_ID}"
}

resource "aws_sqs_queue" "queue" {
  name = "elastic-package-security-lake-queue-${var.TEST_RUN_ID}"
}

# IAM Policy for EventBridge Scheduler
resource "aws_iam_policy" "sqs_access_policy" {
  count       = var.eventbridge_role_arn == null ? 1 : 0
  name        = "sqs-access-policy-${var.TEST_RUN_ID}"
  description = "Policy for EventBridge Scheduler to send messages to SQS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sqs:ReceiveMessage",
          "sqs:SendMessage"
        ],
        Effect   = "Allow"
        Resource = aws_sqs_queue.queue.arn
      }
    ]
  })
}

# IAM Role for EventBridge Scheduler
resource "aws_iam_role" "eventbridge_scheduler_iam_role" {
  count               = var.eventbridge_role_arn == null ? 1 : 0
  name_prefix         = "eb-scheduler-role-${var.TEST_RUN_ID}-"
  managed_policy_arns = [aws_iam_policy.sqs_access_policy.0.arn]
  path                = "/"
  assume_role_policy  = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "scheduler.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

// Simulate Amazon securitylake sending its notification events to SQS. Securitylake
// uses a custom notification format that is different than the AWS S3 event
// notification format.
resource "aws_scheduler_schedule" "eventbridge_scheduler_every1minute" {
  name       = "eventbridge_scheduler_every1minute-${var.TEST_RUN_ID}"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(1 minutes)"

  target {
    arn      = aws_sqs_queue.queue.arn
    role_arn = var.eventbridge_role_arn == null ? aws_iam_role.eventbridge_scheduler_iam_role.0.arn : var.eventbridge_role_arn

    input = jsonencode({
      detail = {
        bucket = {
          name = "elastic-package-security-lake-bucket-${var.TEST_RUN_ID}"
        }
        object = {
          key = "test_parquet_key"
        }
      }
    })
  }
}

resource "aws_s3_object" "object" {
  bucket = aws_s3_bucket.bucket.id
  key    = "test_parquet_key"
  source = "./files/test.gz.parquet"

  depends_on = [aws_sqs_queue.queue]
}
