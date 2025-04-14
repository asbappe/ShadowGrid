variable "aws_region" {
  default = "us-east-1"
}

variable "ami_id" {
  default = "ami-0fc5d935ebf8bc3bc"  # Ubuntu 20.04 in us-east-1 (update for your region)
}

variable "key_name" {
  description = "Your EC2 SSH key name"
}
