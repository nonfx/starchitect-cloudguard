resource "aws_appsync_graphql_api" "example_fail" {
  name = "example-api-fail"
  authentication_type = "API_KEY"

  # No tags are defined
}
