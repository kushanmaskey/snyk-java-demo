# MISCONFIGURATION: Security group open to the world on all ports
resource "aws_security_group" "web" {
  name        = "snyk-demo-web-sg"
  description = "Web server security group"

  # MISCONFIGURATION: SSH open to entire internet
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION: All ports open to entire internet
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # MISCONFIGURATION: Unrestricted outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# MISCONFIGURATION: EC2 instance with public IP, no IMDSv2, unencrypted root volume
resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  security_groups             = [aws_security_group.web.name]
  associate_public_ip_address = true  # MISCONFIGURATION: Public IP exposed

  # MISCONFIGURATION: IMDSv2 not enforced — vulnerable to SSRF metadata attacks
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"  # Should be "required"
    http_put_response_hop_limit = 2           # Should be 1
  }

  root_block_device {
    volume_size = 20
    encrypted   = true  # MISCONFIGURATION: Root volume not encrypted
  }

  tags = {
    Name = "snyk-demo-web"
  }
}
