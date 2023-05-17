resource "aws_kms_key" "kms-s3-files" {
  description = "KMS Key 1"
  deletion_window_in_days = 7
}

resource "aws_s3_bucket" "bucket" {
  bucket = "mys3-abc-notification-check"
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.bucket.id

  queue {
    queue_arn     = aws_sqs_queue.queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".log"
  }
}

resource "aws_s3_object" "object" {
  bucket = aws_s3_bucket.bucket.id
  key = "my-json-json-key"
  source = "./test.json"
  kms_key_id = aws_kms_key.kms-s3-files.arn
}