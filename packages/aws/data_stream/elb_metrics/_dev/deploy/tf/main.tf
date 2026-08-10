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

# t3.micro is not offered in every AZ. Discover AZs that actually offer it
# in the active region instead of hardcoding us-east-1 names.
data "aws_ec2_instance_type_offerings" "t3_micro" {
  filter {
    name   = "instance-type"
    values = ["t3.micro"]
  }

  location_type = "availability-zone"
}

data "aws_subnets" "target" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "availability-zone"
    values = data.aws_ec2_instance_type_offerings.t3_micro.locations
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
cat >/usr/local/bin/ep-http.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        code = {
            "/": 200,
            "/ok": 200,
            "/redirect": 302,
            "/client-error": 404,
            "/server-error": 500,
        }.get(path, 200)
        body = b"OK"
        self.send_response(code)
        if code == 302:
            self.send_header("Location", "/ok")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

HTTPServer(("0.0.0.0", 80), H).serve_forever()
PY
cat >/etc/systemd/system/ep-http.service <<'UNIT'
[Unit]
Description=elastic-package ELB test HTTP server
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ep-http.py
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
  # Use the same AZ-qualified subnet set as the target so the ALB always spans
  # the target's Availability Zone when regions do not offer t3.micro
  # everywhere.
  subnets            = slice(sort(data.aws_subnets.target.ids), 0, min(2, length(data.aws_subnets.target.ids)))

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

# In-VPC client generates continuous HTTP traffic across 2xx/3xx/4xx/5xx paths
# so CloudWatch publishes all HTTPCode_Target_* series for the system test.
resource "aws_instance" "client" {
  ami                         = data.aws_ami.latest_amzn.id
  instance_type               = "t3.micro"
  subnet_id                   = sort(data.aws_subnets.target.ids)[0]
  vpc_security_group_ids      = [aws_security_group.client.id]
  associate_public_ip_address = true
  depends_on                  = [aws_lb_listener.http, aws_lb_target_group_attachment.tg_attachment]

  user_data = <<-EOF
#!/bin/bash
cat >/etc/systemd/system/ep-traffic.service <<'UNIT'
[Unit]
Description=elastic-package ELB traffic generator
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/bin/bash -c 'while true; do for p in / /ok /redirect /client-error /server-error; do curl -s -m 2 -o /dev/null "http://ALB_DNS_PLACEHOLDER$p" || true; done; sleep 1; done'
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
sed -i 's|ALB_DNS_PLACEHOLDER|${aws_lb.alb.dns_name}|g' /etc/systemd/system/ep-traffic.service
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
