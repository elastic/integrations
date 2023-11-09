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

# data "aws_caller_identity" "current" {}

# resource "aws_sqs_queue_policy" "schedule-event-policy" {
#   queue_url = aws_sqs_queue.queue.id

#   policy = <<POLICY
# {
#   "Version": "2012-10-17",
#   "Id": "sqspolicy",
#   "Statement": [
#     {
#       "Sid": "First",
#       "Effect": "Allow",
#       "Principal": "*",
#       "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"],
#       "Resource": "${aws_sqs_queue.queue.arn}"
#     }
#   ]
# }
# POLICY
# }

# resource "aws_iam_role" "event_bridge_sqs_role" {
#   name = "event_bridge_sqs_role"

#   assume_role_policy = jsonencode({
#     "Version" : "2012-10-17",
#     "Statement" : [
#       {
#         "Effect" : "Allow",
#         "Principal" : {
#           "Service" : "scheduler.amazonaws.com"
#         },
#         "Action" : "sts:AssumeRole"
#       }
#     ]
#   })
# }

resource "aws_scheduler_schedule" "eventbridge_scheduler_every1minute" {
  name       = "eventbridge_scheduler_every1minute-${var.TEST_RUN_ID}"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(1 minutes)"

  target {
    arn      = aws_sqs_queue.queue.arn
    role_arn = "arn:aws:iam::144492464627:role/eb-scheduler-role-20231101165501426500000001"

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

output "queue_url" {
  value = aws_sqs_queue.queue.url
}
