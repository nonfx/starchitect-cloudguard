[![Starchitect](./assets/starchitect.png)](https://starchitect.ai)
[Join our community!](https://discord.gg/r48ZahhA)

# Starchitect-CloudGuard

[![Regula Tests](https://github.com/nonfx/starchitect-cloudguard/actions/workflows/regula-test.yml/badge.svg)](https://github.com/nonfx/starchitect-cloudguard/actions/workflows/regula-test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Discord](https://img.shields.io/discord/1306489507499216897)](https://discord.gg/r48ZahhA)

---

Starchitect-CloudGuard is an open-source repository that provides security tests for cloud infrastructure in two ways:

1. Runtime Tests (`/runtime`): Direct security checks against your live cloud accounts (currently supporting AWS)
2. Infrastructure as Code Tests (`/terraform`): Static analysis of your infrastructure-as-code files in Terraform format, supporting both AWS and GCP security benchmarks

Cutting-edge AI-powered test-writing agents craft these tests with a well-defined understanding of cloud security. Each test undergoes meticulous human review by the experienced team at [The Non-Functionional Co.](https://nonfx.com), ensuring high-quality and reliable compliance validation.

This framework is designed to be flexible and extensible. While we currently focus on AWS runtime checks and Terraform static analysis, support for additional cloud providers (like GCP, Azure) and IaC formats (like Pulumi, Bicep, CloudFormation) is constantly growing. If you have specific requirements, open a GitHub issue; our team will be happy to assist.

## Installation

You can install the Starchitect CLI in several ways:

### Using Homebrew

```bash
brew tap nonfx/starkit
brew install starkit
```

### Using npm

```bash
npm install starkit
```

For additional installation platforms and options, check our [releases section](https://github.com/nonfx/starchitect-cloudguard/releases).

## Running Benchmark Tests

You can run all benchmark tests on your live AWS environment using our CLI:

```bash
starkit runtime aws
```

### AWS Credentials Configuration

Before running the tests, you'll need to configure your AWS credentials. Here are two ways to do this:

1. Using Environment Variables
   Export these variables in your terminal:

   ```bash
   export AWS_ACCESS_KEY_ID=<your-access-key>
   export AWS_SECRET_ACCESS_KEY=<your-secret-key>
   ```

2. Using AWS CLI (Recommended)
   First, install the AWS CLI from: https://aws.amazon.com/cli/
   Then, run:
   ```bash
   aws configure
   AWS Access Key ID: [your-access-key]
   AWS Secret Access Key: [your-secret-key]
   Default region name: [your-region]
   Default output format: [json]
   ```

Ref:

- Create access keys: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
- AWS CLI setup guide: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

## Security Benchmark Coverage

| Benchmark                                           | Status |
| --------------------------------------------------- | ------ |
| CIS Amazon Web Services Foundations                 | ✅     |
| CIS Google Cloud Computing Platform Foundation      | ✅     |
| CIS Amazon Web Services Three-tier Web Architecture | ✅     |
| AWS Foundational Security Best Practices            | ✅     |
| CIS Google Cloud Platform Security Foundations      | ✅     |

> All tests are implemented using [Fugue Regula](https://github.com/fugue/regula) for Terraform configurations

> CloudFormation, Pulumi, and Bicep tests are coming soon.

## Contributing

We welcome contributions from the community! To contribute to Starchitect-CloudGuard, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Make your changes and write tests.
4. Submit a pull request.
5. Await review and approval.

For more details, refer to the [Contributing Guide](CONTRIBUTING.md).

The Starchitect-CloudGuard community is vibrant and collaborative. Join us on our [Discord server](https://discord.gg/r48ZahhA) to connect, ask questions, share insights, and contribute to the project.
