provider "aws" {
  alias = "failing"
  region = "us-west-2"
}

resource "aws_organizations_policy" "failing_policy" {
  name     = "example-policy"
  description = "This policy does not enforce tags"
  type     = "SERVICE_CONTROL_POLICY"
  content  = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  })
}
