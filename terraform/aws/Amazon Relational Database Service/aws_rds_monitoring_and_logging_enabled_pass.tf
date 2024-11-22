provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_iam_role" "rds_monitoring_role" {
  provider = aws.passing
  name               = "rds-monitoring-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_policy" {
  provider = aws.passing
  role       = aws_iam_role.rds_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "passing_example" {
  provider             = aws.passing
  identifier           = "passing-rds-instance"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true

  # Monitoring is enabled
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring_role.arn

  # Logging is enabled
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
}
