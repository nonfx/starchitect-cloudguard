provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create GraphQL API with proper configuration
resource "aws_appsync_graphql_api" "pass_api" {
  provider = aws.pass_aws
  name = "pass-api-cache"
  authentication_type = "API_KEY"
}

# Create API cache with encryption enabled
resource "aws_appsync_api_cache" "pass_cache" {
  provider = aws.pass_aws
  api_id = aws_appsync_graphql_api.pass_api.id
  api_caching_behavior = "FULL_REQUEST_CACHING"
  type = "SMALL"
  ttl = 3600
  at_rest_encryption_enabled = true
}