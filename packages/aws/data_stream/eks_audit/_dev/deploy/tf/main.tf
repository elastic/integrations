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
  # Mirror the log group and stream naming that EKS control-plane logging uses, so the
  # default /aws/eks/ prefix and kube-apiserver-audit stream prefix both match.
  eks_audit_log_group  = "/aws/eks/test-${var.TEST_RUN_ID}/cluster"
  eks_audit_log_stream = "kube-apiserver-audit-${var.TEST_RUN_ID}"

  eks_audit_lines = [
    for line in split("\n", file("${path.module}/files/eks_audit.log")) : line
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
      team     = "security-service-integrations"
      project  = "integrations-aws-package"
    }
  }
}

resource "aws_cloudwatch_log_group" "eks_audit" {
  name              = local.eks_audit_log_group
  retention_in_days = 1
}

resource "aws_cloudwatch_log_stream" "eks_audit" {
  name           = local.eks_audit_log_stream
  log_group_name = aws_cloudwatch_log_group.eks_audit.name

  depends_on = [aws_cloudwatch_log_group.eks_audit]
}

# CloudWatch discards events older than 14 days, so timestamps are taken at apply time.
resource "time_static" "push_time" {}

resource "null_resource" "push_eks_audit_logs" {
  depends_on = [aws_cloudwatch_log_stream.eks_audit]

  triggers = {
    logs_hash = filemd5("${path.module}/files/eks_audit.log")
  }

  provisioner "local-exec" {
    command     = <<-EOT
    set -e

    # unset AWS_PROFILE to use environment credentials
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
      LOG_GROUP_NAME  = aws_cloudwatch_log_group.eks_audit.name
      LOG_STREAM_NAME = aws_cloudwatch_log_stream.eks_audit.name
      # jsonencode keeps the embedded JSON escaping of each audit line intact.
      LOG_EVENTS = jsonencode([
        for index, line in local.eks_audit_lines : {
          timestamp = (time_static.push_time.unix + index) * 1000
          message   = line
        }
      ])
    }
  }
}

data "aws_region" "current" {}

output "eks_audit_log_group_arn" {
  value = aws_cloudwatch_log_group.eks_audit.arn
}

output "eks_audit_log_group_name" {
  value = aws_cloudwatch_log_group.eks_audit.name
}

output "region_name" {
  value = data.aws_region.current.name
}
