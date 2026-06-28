# Example secure baseline configuration for demonstration.

resource "aws_security_group" "restricted_ssh" {
  name        = "restricted-ssh"
  description = "Example restricted SSH security group"

  ingress {
    description = "SSH from trusted private range"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}