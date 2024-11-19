resource "aws_timestreamwrite_database" "example" {
  database_name = "example-timestream-db"
}

resource "aws_iam_policy" "timestream_policy" {
  name        = "timestreamAccessPolicy"
  description = "Allow access to timestream tables"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "timestream:Select"
        ],
        Resource = "arn:aws:timestream:us-east-1:123456789012:database/example_database/table/example_table"
      }
    ]
  })
}

resource "aws_iam_role_policy" "app_role_policy" {
  name = "AppRolePolicy"
  role = aws_iam_role.app_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "timestream:Select"
        ],
        Resource = "arn:aws:timestream:us-east-1:123456789012:database/example_database/table/example_table"
      }
    ]
  })
}

resource "aws_iam_user_policy" "user_policy" {
  name = "UserPolicy"
  user = aws_iam_user.user.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "timestream:Select"
        ],
        Resource = "arn:aws:timestream:us-east-1:123456789012:database/example_database/table/example_table"
      }
    ]
  })
}

resource "aws_iam_group_policy" "group_policy" {
  name = "GroupPolicy"
  group = aws_iam_group.group.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "timestream:Select"
        ],
        Resource = "arn:aws:timestream:us-east-1:123456789012:database/example_database/table/example_table"
      }
    ]
  })
}


