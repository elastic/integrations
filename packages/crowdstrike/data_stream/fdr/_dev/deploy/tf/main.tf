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

resource "aws_s3_bucket" "crowdstrike_fdr" {
  bucket = "${var.bucket_name}-${var.TEST_RUN_ID}"
}

resource "aws_s3_object" "crowdstrike_data" {
  bucket = aws_s3_bucket.crowdstrike_fdr.id
  key    = "data"
  source = "./files/fdr-sample.log"
}

resource "aws_s3_object" "crowdstrike_aidmaster" {
  bucket = aws_s3_bucket.crowdstrike_fdr.id
  key    = "fdrv2/aidmaster"
  source = "./files/fdr-0_aidmaster.log"
}

resource "aws_s3_object" "crowdstrike_userinfo" {
  bucket = aws_s3_bucket.crowdstrike_fdr.id
  key    = "fdrv2/userinfo"
  source = "./files/fdr-0_userinfo.log"
}

resource "aws_sqs_queue" "crowdstrike_queue" {
  name = "elastic-package-crowdstrike-queue-${var.TEST_RUN_ID}"
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
        Resource = aws_sqs_queue.crowdstrike_queue.arn
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

// Simulate CrowdStrike sending its notification events to SQS. CrowdStrike
// uses a custom notification format that is different than the AWS S3 event
// notification format.
resource "aws_scheduler_schedule" "eventbridge_scheduler_every1minute" {
  name       = "eventbridge_scheduler_crowdstrike_fdr_sqs-${var.TEST_RUN_ID}"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(1 minutes)"

  target {
    arn      = aws_sqs_queue.crowdstrike_queue.arn
    role_arn = var.eventbridge_role_arn == null ? aws_iam_role.eventbridge_scheduler_iam_role.0.arn : var.eventbridge_role_arn

    input = jsonencode({
      cid        = "ffffffff15754bcfb5f9152ec7ac90ac"
      timestamp  = 1625677488615
      fileCount  = 3
      totalSize  = 120161
      bucket     = aws_s3_bucket.crowdstrike_fdr.id
      pathPrefix = "data/f0714ca5-3689-448d-b5cc-582a6f7a56b1"
      "files" : [
        {
          "path" : aws_s3_object.crowdstrike_data.key,
          "size" : 115258,
          "checksum" : "c24b5525ad5d4b3ff92bb3c9c002bdc7"
        },
        {
          "path" : aws_s3_object.crowdstrike_aidmaster.key,
          "size" : 4414,
          "checksum" : "a06a88462e6950f0be3bb83230047e87"
        },
        {
          "path" : aws_s3_object.crowdstrike_userinfo.key,
          "size" : 489,
          "checksum" : "349c96ed5531edce2233ad417123736d"
        }
      ]
    })
  }
}
