provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create GraphQL API without encryption
resource "aws_appsync_graphql_api" "fail_api" {
  provider = aws.fail_aws
  name = "fail-api-cache"
  authentication_type = "API_KEY"
}

# Create API cache without encryption enabled
resource "aws_appsync_api_cache" "fail_cache" {
  provider = aws.fail_aws
  api_id = aws_appsync_graphql_api.fail_api.id
  api_caching_behavior = "FULL_REQUEST_CACHING"
  type = "SMALL"
  ttl = 3600
  at_rest_encryption_enabled = false
}