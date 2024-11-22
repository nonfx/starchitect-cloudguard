# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create an SSM document with private access (passing case)
resource "aws_ssm_document" "pass_doc" {
  name          = "pass-test-doc"
  document_type = "Command"

  # Document content defining a simple Linux command
  content = jsonencode({
    schemaVersion = "1.2"
    description   = "Check ip configuration of a Linux instance."
    parameters    = {}
    mainSteps = [
      {
        action = "aws:runShellScript"
        name   = "ipConfig"
        inputs = {
          runCommand = ["ifconfig"]
        }
      }
    ]
  })

  # No permissions block means document is private by default

  tags = {
    Environment = "production"
    Security    = "private"
  }
}