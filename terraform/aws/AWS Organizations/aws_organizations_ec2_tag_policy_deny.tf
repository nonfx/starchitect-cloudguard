provider "aws" {
  region = "us-west-2"
}

resource "aws_organizations_organization" "org" {
  feature_set = "ALL"
}

resource "aws_organizations_policy" "example_scp" {
  name = "example_scp"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = {
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }
  })
  type = "SERVICE_CONTROL_POLICY"
}

resource "aws_organizations_policy" "example_tag_policy" {
  name = "example_tag_policy"
  content = jsonencode({
    tags = {
      costcenter = {
        tag_key = {
          assign = "CostCenter"
        }
        tag_value = {
          assign = [
            "100",
            "200"
          ]
        }
      }
    }
  })
  type = "TAG_POLICY"
}
