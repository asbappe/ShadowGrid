output "ec2_public_ip" {
  value = aws_instance.shadowgrid.public_ip
}
