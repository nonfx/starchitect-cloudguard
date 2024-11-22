provider "aws" {
  region = "us-west-2"
}

resource "aws_organizations_organization" "org" {
  feature_set = "ALL"
}

resource "aws_organizations_policy" "example_ec2_tag_policy" {
  name = "example_ec2_tag_policy"
  content = jsonencode({
    tags = {
      environment = {
        tag_key = {
          assign = "Environment"
        }
        tag_value = {
          assign = [
            "Production",
            "Development",
            "Testing"
          ]
        }
        operators_allowed_for_child_policies = ["ALLOW_VALUE_ONLY", "ENFORCED_FOR"]
        enforced_for = {
          assign = [
            "ec2:instance",
            "ec2:image",
            "ec2:reserved-instances"
          ]
        }
      }
    }
  })
  type = "TAG_POLICY"
}
