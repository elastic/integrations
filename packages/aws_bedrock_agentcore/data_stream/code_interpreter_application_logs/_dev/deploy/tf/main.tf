variable "TEST_RUN_ID" {
  default = "detached"
}

terraform {
  required_providers {
    aws  = { source = "hashicorp/aws" }
    null = { source = "hashicorp/null" }
    time = { source = "hashicorp/time" }
  }
}

locals {
  # Use a neutral prefix for system tests; production delivery uses `/aws/vendedlogs/...`.
  code_interpreter_log_group  = "/elastic-package/aws_bedrock_agentcore/code-interpreter-${var.TEST_RUN_ID}"
  code_interpreter_log_stream = "BedrockAgentCoreCodeInterpreter_ApplicationLogs"

  code_interpreter_lines = [
    for line in split("\n", file("${path.module}/files/code-interpreter-sample.log")) : replace(
      line,
      "111122223333",
      data.aws_caller_identity.current.account_id
    )
    if trimspace(line) != ""
  ]
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
      team     = "obs-signals-integrations-team"
      project  = "integrations-aws_bedrock_agentcore-package"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "code_interpreter" {
  name              = local.code_interpreter_log_group
  retention_in_days = 1
}

resource "aws_cloudwatch_log_stream" "code_interpreter" {
  name           = local.code_interpreter_log_stream
  log_group_name = aws_cloudwatch_log_group.code_interpreter.name

  depends_on = [aws_cloudwatch_log_group.code_interpreter]
}

resource "time_static" "push_time" {
  triggers = {
    run_id    = var.TEST_RUN_ID
    logs_hash = filemd5("${path.module}/files/code-interpreter-sample.log")
  }
}

resource "null_resource" "push_code_interpreter_logs" {
  depends_on = [aws_cloudwatch_log_stream.code_interpreter]

  triggers = {
    run_id    = var.TEST_RUN_ID
    logs_hash = filemd5("${path.module}/files/code-interpreter-sample.log")
  }

  provisioner "local-exec" {
    command     = <<-EOT
    set -e

    unset AWS_PROFILE

    if ! command -v aws >/dev/null 2>&1; then
      apt-get update -qq
      apt-get install -y -qq curl unzip > /dev/null 2>&1

      curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
      unzip -q -o /tmp/awscliv2.zip -d /tmp
      /tmp/aws/install 2>/dev/null || /tmp/aws/install --update
    fi

    aws logs put-log-events \
        --region "$AWS_REGION" \
        --log-group-name "$LOG_GROUP_NAME" \
        --log-stream-name "$LOG_STREAM_NAME" \
        --log-events "$LOG_EVENTS"
    EOT
    interpreter = ["/bin/sh", "-c"]

    environment = {
      LOG_GROUP_NAME  = aws_cloudwatch_log_group.code_interpreter.name
      LOG_STREAM_NAME = aws_cloudwatch_log_stream.code_interpreter.name
      LOG_EVENTS = jsonencode([
        for index, line in local.code_interpreter_lines : {
          timestamp = (time_static.push_time.unix + index) * 1000
          message   = line
        }
      ])
    }
  }
}

data "aws_region" "current" {}

output "code_interpreter_log_group_arn" {
  value = aws_cloudwatch_log_group.code_interpreter.arn
}

output "region_name" {
  value = data.aws_region.current.region
}
