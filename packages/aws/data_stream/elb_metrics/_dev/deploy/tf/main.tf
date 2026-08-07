variable "TEST_RUN_ID" {
  default = "detached"
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
      team     = "obs-infraobs-integrations"
      project  = "integrations-aws-package"
    }
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# t3.micro is not offered in every AZ (e.g. us-east-1e). Prefer a known-good AZ.
data "aws_subnets" "target" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "availability-zone"
    values = ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1f"]
  }
}

data "aws_ami" "latest_amzn" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

data "aws_caller_identity" "current" {}

resource "aws_security_group" "alb" {
  name        = "elastic-package-elb-alb-${var.TEST_RUN_ID}"
  description = "Allow HTTP to internal ALB for elastic-package elb_metrics system test"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.client.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

resource "aws_security_group" "target" {
  name        = "elastic-package-elb-target-${var.TEST_RUN_ID}"
  description = "Allow HTTP from ALB to target for elastic-package elb_metrics system test"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

resource "aws_security_group" "client" {
  name        = "elastic-package-elb-client-${var.TEST_RUN_ID}"
  description = "Egress client used to generate ALB HTTPCode_Target_* traffic"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

resource "aws_instance" "target" {
  ami                         = data.aws_ami.latest_amzn.id
  instance_type               = "t3.micro"
  subnet_id                   = sort(data.aws_subnets.target.ids)[0]
  vpc_security_group_ids      = [aws_security_group.target.id]
  associate_public_ip_address = true

  user_data = <<-EOF
              #!/bin/bash
              cat >/etc/systemd/system/ep-http.service <<'UNIT'
              [Unit]
              Description=elastic-package ELB test HTTP server
              After=network.target
              [Service]
              ExecStart=/usr/bin/python3 -c "from http.server import BaseHTTPRequestHandler,HTTPServer\nclass H(BaseHTTPRequestHandler):\n  def do_GET(self):\n    self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'OK')\n  def log_message(self,*a): pass\nHTTPServer(('0.0.0.0',80),H).serve_forever()"
              Restart=always
              [Install]
              WantedBy=multi-user.target
              UNIT
              systemctl daemon-reload
              systemctl enable --now ep-http.service
              EOF

  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

resource "aws_lb_target_group" "tg" {
  name     = "ep-elb-${var.TEST_RUN_ID}"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 10
    matcher             = "200"
  }

  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

resource "aws_lb_target_group_attachment" "tg_attachment" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.target.id
  port             = 80
}

# Internal ALB: reachable from VPC clients even when corporate networks block
# public ALB:80. Metricbeat still scrapes CloudWatch over the AWS API.
resource "aws_lb" "alb" {
  name               = "ep-elb-${var.TEST_RUN_ID}"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = slice(sort(data.aws_subnets.default.ids), 0, min(2, length(data.aws_subnets.default.ids)))

  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# In-VPC client generates continuous HTTP traffic so CloudWatch publishes
# HTTPCode_Target_* (and non-zero RequestCount) for the system test.
resource "aws_instance" "client" {
  ami                         = data.aws_ami.latest_amzn.id
  instance_type               = "t3.micro"
  subnet_id                   = sort(data.aws_subnets.target.ids)[0]
  vpc_security_group_ids      = [aws_security_group.client.id]
  associate_public_ip_address = true
  depends_on                  = [aws_lb_listener.http, aws_lb_target_group_attachment.tg_attachment]

  user_data = <<-EOF
              #!/bin/bash
              cat >/etc/systemd/system/ep-traffic.service <<UNIT
              [Unit]
              Description=elastic-package ELB traffic generator
              After=network-online.target
              Wants=network-online.target
              [Service]
              ExecStart=/bin/bash -c 'while true; do curl -s -m 2 "http://${aws_lb.alb.dns_name}/" >/dev/null || true; sleep 1; done'
              Restart=always
              [Install]
              WantedBy=multi-user.target
              UNIT
              systemctl daemon-reload
              systemctl enable --now ep-traffic.service
              EOF

  tags = {
    Name = "elastic-package-test-${var.TEST_RUN_ID}"
  }
}

output "alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "alb_arn" {
  value = aws_lb.alb.arn
}
