resource "aws_appsync_graphql_api" "example_pass" {
  name = "example-api-pass"
  authentication_type = "AMAZON_COGNITO_USER_POOLS"
}
