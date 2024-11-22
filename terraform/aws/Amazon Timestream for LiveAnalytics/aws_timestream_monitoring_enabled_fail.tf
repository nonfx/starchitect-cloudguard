provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_timestreamwrite_database" "failing_example" {
  provider = aws.failing
  database_name = "failing_example"
}

resource "aws_cloudwatch_log_group" "failing_example" {
  provider = aws.failing
  name = "/aws/timestream/database/${aws_timestreamwrite_database.failing_example.id}"
}
