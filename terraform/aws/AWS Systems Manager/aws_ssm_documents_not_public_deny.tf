# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create an SSM document with public access (failing case)
resource "aws_ssm_document" "fail_doc" {
  name          = "fail-test-doc"
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

  # Making document public by allowing all AWS accounts
  permissions = {
    type        = "Share"
    account_ids = ["All"]
  }

  tags = {
    Environment = "test"
  }
}
