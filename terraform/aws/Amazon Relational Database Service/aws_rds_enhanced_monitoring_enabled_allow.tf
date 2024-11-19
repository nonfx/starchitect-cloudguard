provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create IAM role for enhanced monitoring
resource "aws_iam_role" "pass_monitoring_role" {
  provider = aws.pass_aws
  name = "rds-enhanced-monitoring-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

# Attach required monitoring policy to the IAM role
resource "aws_iam_role_policy_attachment" "pass_monitoring_policy" {
  provider = aws.pass_aws
  role = aws_iam_role.pass_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# Create RDS instance with valid enhanced monitoring configuration
resource "aws_db_instance" "pass_test" {
  provider = aws.pass_aws
  identifier = "pass-test-db"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  
  # Valid monitoring configuration - interval set to 60 seconds and role ARN specified
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.pass_monitoring_role.arn
  
  tags = {
    Environment = "production"
    Purpose = "monitoring-test"
  }
}
