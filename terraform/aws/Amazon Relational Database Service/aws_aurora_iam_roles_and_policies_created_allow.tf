provider "aws" {
  region = "us-west-2"
}

resource "aws_rds_cluster" "aurora_cluster" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
}

resource "aws_rds_cluster_instance" "aurora_instance" {
  identifier         = "aurora-cluster-demo-instance"
  cluster_identifier = aws_rds_cluster.aurora_cluster.id
  instance_class     = "db.r5.large"
  engine             = aws_rds_cluster.aurora_cluster.engine
  engine_version     = aws_rds_cluster.aurora_cluster.engine_version
}

resource "aws_iam_role" "aurora_role" {
  name = "aurora_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_policy" "aurora_policy" {
  name        = "aurora_rds_policy"
  path        = "/"
  description = "IAM policy for Aurora RDS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "rds:Describe*",
          "rds:List*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "aurora_attachment" {
  role       = aws_iam_role.aurora_role.name
  policy_arn = aws_iam_policy.aurora_policy.arn
}

resource "aws_rds_cluster_role_association" "aurora_role_association" {
  db_cluster_identifier = aws_rds_cluster.aurora_cluster.id
  feature_name          = "S3_INTEGRATION"
  role_arn              = aws_iam_role.aurora_role.arn
}
