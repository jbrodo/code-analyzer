resource "aws_security_group" "ssh" {
  name        = "fixture-ssh"
  description = "Gruppo di sicurezza di prova"

  ingress {
    description = "SSH da ovunque"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "fixture-iac-bucket"
}
