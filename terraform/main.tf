provider "aws" {
  region = var.aws_region
}

resource "aws_instance" "shadowgrid" {
  ami           = var.ami_id             # Ubuntu 20.04 (for example)
  instance_type = "t2.micro"
  key_name      = var.key_name           # Your SSH key
  user_data     = file("cloud_init.sh")  # Bootstraps server
  tags = {
    Name = "shadowgrid-instance"
  }

  vpc_security_group_ids = [aws_security_group.sg.id]
}

resource "aws_security_group" "sg" {
  name        = "shadowgrid-sg"
  description = "Allow inbound HTTP/Streamlit traffic"

  ingress {
    from_port   = 8501
    to_port     = 8501
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
