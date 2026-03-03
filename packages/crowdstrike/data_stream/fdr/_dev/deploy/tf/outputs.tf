output "queue_url" {
  value = aws_sqs_queue.crowdstrike_queue.url
}
