provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user" "example" {
  name = "example-user"
}

resource "aws_iam_saml_provider" "example" {
  name                   = "example-saml-provider"
  saml_metadata_document = "example-saml-metadata-document"
}

resource "aws_organizations_organization" "example" {
  aws_service_access_principals = ["service1.amazonaws.com", "service2.amazonaws.com"]
  feature_set                   = "ALL"
}
