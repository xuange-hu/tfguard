"""A deliberately hostile Terraform workspace.

The demo is not a style sample: every block in it is wrong in a different way,
so it is the thing CI can point at and say "all 40 rules still fire". It is
also the first thing a visitor runs, so the files are separated the way a real
workspace is separated rather than being one document.

One rule is deliberately *not* in the base workspace: TFG060 (no remote
backend) and TFG061 (remote backend that is not encrypted) are mutually
exclusive, so the demo ships the backend in its own file and removing that
file is what surfaces the other rule.
"""

from __future__ import annotations

import os

VERSIONS = """# versions.tf — the provider is unpinned and the CLI version is unconstrained.
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
"""

# The backend sits in its own file so that deleting it turns TFG061 into TFG060.
STATE = """# state.tf — remote, but the state file is stored unencrypted.
terraform {
  backend "s3" {
    bucket = "demo-tfstate"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}
"""

VARIABLES = """variable "db_password" {
  type    = string
  default = "Sup3rS3cretDbValue"
}

variable "api_token" {
  type    = string
  default = "tok_live_9f2c41ab7d"
}

variable "relay_secret" {
  default = local.relayed
}

variable "session_secret" {
  type = string
}
"""

LOCALS = """locals {
  relayed = "RelayedS3cretValue"
}
"""

VPC = """resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_vpc" "audited" {
  cidr_block = "10.1.0.0/16"
}

# This one has a flow log, so tfguard must stay quiet about it.
resource "aws_flow_log" "audited" {
  vpc_id          = aws_vpc.audited.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow.arn
  log_destination = aws_s3_bucket.logs.arn
}
"""

SECURITY_GROUPS = """resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {}
}

# egress = [] is a decision, not an omission: tfguard records it and moves on.
resource "aws_security_group" "private" {
  name   = "private"
  egress = []
}

resource "aws_security_group_rule" "ssh_from_anywhere" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.private.id
}

resource "aws_security_group_rule" "peer_to_nowhere" {
  type                      = "ingress"
  from_port                 = 5432
  to_port                   = 5432
  protocol                  = "tcp"
  source_security_group_id  = aws_security_group.missing.id
  security_group_id         = aws_security_group.private.id
}
"""

COMPUTE = """resource "aws_instance" "bastion" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web.id]
}

resource "aws_instance" "app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"
  tags = {
    Password = var.db_password
  }
  user_data = <<-EOT
    #!/bin/bash
    echo "db_password=InlineS3cretInUserData" >> /etc/app.conf
  EOT
}

resource "aws_launch_template" "workers" {
  name_prefix   = "worker-"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"

  network_interfaces {
    associate_public_ip_address = true
  }
}

resource "aws_lb" "public" {
  name               = "public"
  load_balancer_type = "application"
  internal           = false
  subnets            = ["subnet-abc"]
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_efs_file_system" "shared" {
  encrypted = false
}
"""

DATA = """resource "aws_db_instance" "main" {
  identifier       = "main"
  engine           = "postgres"
  instance_class   = "db.t3.micro"
  password         = "DirectLiteralDatabasePassword"
  storage_encrypted = false
  publicly_accessible = true
}

resource "aws_db_instance" "second" {
  identifier       = "second"
  engine           = "postgres"
  instance_class   = "db.t3.micro"
  password         = var.db_password
  storage_encrypted = false
}

resource "aws_s3_bucket" "logs" {
  bucket = "demo-logs"
}

resource "aws_s3_bucket" "public" {
  bucket = "demo-public"
  acl    = "public-read"

  public_access_block {
    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
  }
}

resource "aws_kms_key" "main" {
  description           = "demo"
  enable_key_rotation   = false
}

resource "aws_cloudtrail" "audit" {
  name                          = "demo"
  s3_bucket_name                = aws_s3_bucket.logs.id
  enable_log_file_validation    = false
  is_multi_region_trail         = false
}
"""

IAM = """data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["arn:aws:s3:::demo-logs/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_iam_role" "admin" {
  name               = "demo-admin"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_role" "lambda" {
  name = "demo-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = "*"
    }]
  })
}

resource "aws_iam_role" "flow" {
  name = "demo-flow"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "inline" {
  name = "demo-inline"
  role = aws_iam_role.admin.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
"""

OUTPUTS = """output "db_password" {
  value = var.db_password
}

output "api_token" {
  value     = var.api_token
  sensitive = true
}
"""

MODULES = """module "vpc" {
  source = "git::https://example.com/terraform-modules/vpc.git"
}
"""

FILES = {
    "versions.tf": VERSIONS,
    "state.tf": STATE,
    "variables.tf": VARIABLES,
    "locals.tf": LOCALS,
    "vpc.tf": VPC,
    "security_groups.tf": SECURITY_GROUPS,
    "compute.tf": COMPUTE,
    "data.tf": DATA,
    "iam.tf": IAM,
    "modules.tf": MODULES,
    "outputs.tf": OUTPUTS,
}


def write_demo(directory: str = "demo-workspace") -> list[str]:
    """Write the demo workspace and return the paths written."""
    os.makedirs(directory, exist_ok=True)
    written = []
    for name, text in FILES.items():
        path = os.path.join(directory, name)
        # encoding is explicit: the Windows runner defaults to cp1252 and the
        # demo carries non-ASCII in its comments.
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        written.append(path)
    return written


def demo_text() -> dict[str, str]:
    return dict(FILES)
