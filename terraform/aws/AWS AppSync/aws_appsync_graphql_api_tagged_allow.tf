resource "aws_appsync_graphql_api" "example_pass" {
  name = "example-api-pass"
  authentication_type = "API_KEY"

  tags = {
    Project = "Development"
    Owner = "TeamA"
  }
}
