variable "TEST_RUN_ID" {
  default = "detached"
}

locals {
  activemq_log_group_name_general = "/aws/activemq/broker/test-${var.TEST_RUN_ID}/general"
  activemq_log_stream_name_general = "activemq-log-stream-general"

  region = "us-east-1"
}

provider "aws" {
  region = local.region
  
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

resource "aws_cloudwatch_log_group" "activemq_log_group" {
    name = local.activemq_log_group_name_general
}

resource "aws_cloudwatch_log_stream" "activemq_log_stream" {
    name = local.activemq_log_stream_name_general
    log_group_name = local.activemq_log_group_name_general

    depends_on = [aws_cloudwatch_log_group.activemq_log_group]
}

# Push data to CloudWatch log stream. Workaround for https://github.com/elastic/elastic-package/issues/3206
resource "null_resource" "push_logs" {
    depends_on = [ aws_cloudwatch_log_stream.activemq_log_stream ]

    triggers = {
        logs_hash = filemd5("${path.module}/files/activemq_general.log")
    }

    provisioner "local-exec" {
      command     = <<-EOT
      set -e

      # unset AWS_PROFILE to use environment credentials
      unset AWS_PROFILE

      apt-get update -qq
      apt-get install -y -qq curl unzip > /dev/null 2>&1
      
      # download AWS CLI 
      curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
      unzip -q -o /tmp/awscliv2.zip -d /tmp
      /tmp/aws/install 2>/dev/null || /tmp/aws/install --update
      

      BASE_TS=$(date +%s)
      COUNTER=0
      EVENTS='['
      FIRST=true
      
      while IFS= read -r line || [ -n "$line" ]; do
          [ -z "$line" ] && continue

          # we have to take current timestamp to generate logs as events with timestamp older than 14 days are 
          # discarded by CloudWatch https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
        
          CURRENT_TS=$((BASE_TS + COUNTER))
          FORMATTED_TS=$(date -u -d "@$CURRENT_TS" '+%Y-%m-%d %H:%M:%S,000' 2>/dev/null || date -u -r $CURRENT_TS '+%Y-%m-%d %H:%M:%S,000')
          CLOUD_WATCH_TS=$((CURRENT_TS * 1000))

          REPLACED_LINE=$(echo "$line" | sed "s|<TIMESTAMP>|$FORMATTED_TS|")
          ESCAPED=$(echo "$REPLACED_LINE" | sed 's/"/\\"/g')

          if [ "$FIRST" = true ]; then
              FIRST=false
          else
              EVENTS="$EVENTS,"
          fi

          EVENTS="$EVENTS{\"timestamp\":$CLOUD_WATCH_TS,\"message\":\"$ESCAPED\"}"
          COUNTER=$((COUNTER + 1))
      done < "${path.module}/files/activemq_general.log"
      
      EVENTS="$EVENTS]"
      
      /usr/local/bin/aws logs put-log-events \
          --region "$AWS_REGION" \
          --log-group-name "$LOG_GROUP_NAME" \
          --log-stream-name "$LOG_STREAM_NAME" \
          --log-events "$EVENTS"

      EOT

      interpreter = ["/bin/sh", "-c"]

      environment = {
        LOG_GROUP_NAME        = aws_cloudwatch_log_group.activemq_log_group.name
        LOG_STREAM_NAME       = aws_cloudwatch_log_stream.activemq_log_stream.name
        SAMPLE_LOG_FILE       = "${path.module}/files/activemq_general.log"
        AWS_REGION            = local.region
        AWS_DEFAULT_REGION    = local.region
      }
    }
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.activemq_log_group.arn
}
