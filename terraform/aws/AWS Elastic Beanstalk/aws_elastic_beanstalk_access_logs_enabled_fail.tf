resource "aws_elastic_beanstalk_application" "example_app" {
  name        = "example-app"
  description = "Example Elastic Beanstalk Application"
}

resource "aws_elastic_beanstalk_environment" "example_env" {
  name                = "example-env"
  application         = aws_elastic_beanstalk_application.example_app.name
  solution_stack_name = "64bit Amazon Linux 2 v3.4.9 running Python 3.8"

  tier = "WebServer"

  # Access logs are not enabled
}
