resource "aws_sqs_queue" "queue" {
  name   = "s3-event-notification-queue"
  policy = <<POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sqs.SendMessage",
            "Resource": "arn:aws:sqs:*:*:s3-event-notification-queue",
            "Condition": {
                "ArnEquals": { "aws:SourceArn": "${aws_s3_bucket.bucket.arn}" }
            }
        }
    ]
  }
  POLICY
}