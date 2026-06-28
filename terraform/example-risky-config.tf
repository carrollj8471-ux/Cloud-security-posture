# Example risky configuration for security review demonstration only.
# Do not apply this configuration.

resource "aws_security_group" "risky_ssh" {
  name        = "risky-ssh-open-to-internet"
  description = "Example risky security group"

  ingress {
    description = "Risky SSH from internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}