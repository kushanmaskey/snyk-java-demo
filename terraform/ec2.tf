resource "aws_security_group" "web" {
  name        = "snyk-demo-web-sg"
  description = "Web server security group"

  # HTTPS traffic from the internet — only what the web server needs
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP traffic (redirects to HTTPS)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH restricted to a known CIDR — supply your office/VPN IP via variable
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Outbound HTTPS only — app only needs to call external APIs
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  security_groups             = [aws_security_group.web.name]
  # No direct public IP — traffic reaches the instance via a load balancer in the public subnet
  associate_public_ip_address = false

  # IMDSv2 enforced — blocks SSRF-based metadata credential theft
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1           # blocks container access to metadata
  }

  root_block_device {
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name = "snyk-demo-web"
  }
}

variable "allowed_ssh_cidr" {
  description = "CIDR range allowed to SSH — set to your office or VPN IP, e.g. 203.0.113.0/24"
  type        = string
}
