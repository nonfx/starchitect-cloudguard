provider "aws" {
  region = "us-west-2"
}

resource "aws_organizations_policy" "tag_policy" {
  name        = "TagPolicy"
  description = "Enforces tagging rules across the organization"
  content     = <<POLICY
{
  "tags": {
    "mandatory": {
      "tag-key": {
        "value": "Environment",
        "enforced-for": ["ec2:instance", "s3:bucket"]
      }
    }
  }
}
POLICY

  type = "TAG_POLICY"
}
resource "aws_organizations_policy_attachment" "tag_policy_attachment" {
  policy_id = aws_organizations_policy.tag_policy.id
  target_id = aws_organizations_organization.root_id
}

data "aws_organizations_organization" "current" {}

output "tag_policy_id" {
  value = aws_organizations_policy.tag_policy.id
}

output "attached_target" {
  value = aws_organizations_policy_attachment.tag_policy_attachment.target_id
}
