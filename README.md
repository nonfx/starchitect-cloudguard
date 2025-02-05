[![Starchitect](./assets/starchitect.png)](https://starchitect.ai)
[Join our community!](https://discord.gg/kDTtfpgFFq)

# Starchitect-CloudGuard

[![Regula Tests](https://github.com/nonfx/starchitect-cloudguard/actions/workflows/regula-test.yml/badge.svg)](https://github.com/nonfx/starchitect-cloudguard/actions/workflows/regula-test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Discord](https://img.shields.io/discord/1306489507499216897)](https://discord.gg/kDTtfpgFFq)

---

![Starkit Demo](./assets/starkit.gif)

Starchitect-CloudGuard is an AI-powered comprehensive security testing framework with a powerful CLI that lets you run the same set of security tests across your entire development lifecycle - during local development, in CI/CD pipelines before deployment, and in your live cloud environment after deployment.

## Key Features

- **Runtime Security Checks**: Validate your live cloud infrastructure

  - Direct security assessment of cloud environments
  - Currently supports AWS (GCP, Azure coming soon)
  - Multiple log formats: JSON, stdout (Integration to log buckets,eg:s3 coming soon)
  - Parallel and concurrent test execution capabilities

- **Static Analysis (SAST)**: Analyze your Infrastructure as Code before deployment

  - Currently supports Terraform configurations for AWS and GCP
  - Validates against established security benchmarks
  - Integration with CI/CD pipelines
  - Can be used as terraform provider [here](https://github.com/nonfx/terraform-provider-starchitect)

- **AI-Powered Test Generation**: Automated creation of high-quality security tests
  - Cutting-edge AI agents craft tests with deep cloud security understanding
  - Meticulous human review by [The Non-Functionional Co.](https://nonfx.com) team
  - Ensures reliable and comprehensive compliance validation

This framework is designed to be flexible and extensible. While we currently focus on AWS runtime checks and Terraform static analysis, support for additional cloud providers (like GCP, Azure) and IaC formats (like Pulumi, Bicep, CloudFormation) is constantly growing. If you have specific requirements, open a GitHub issue; our team will be happy to assist.

## Installation

The fastest way to get started with the CLI is through a Node.js runtime, but we also provide Homebrew taps, deb/rpm packages, and standalone binaries for major platforms.

```bash
# If you have npm
npx -y starkit

# If you have bun
bunx starkit
```

You can install the Starchitect CLI in several ways:

### Using Homebrew

```bash
brew tap nonfx/starkit
brew install starkit
```

### Using npm

```bash
npm install -g starkit
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

## Project Structure

The repository is organized into three main directories:

- `/runtime` - Contains all runtime security tests written in JavaScript

  - `/runtime/aws` - AWS service-specific tests (e.g., Lambda, CloudTrail, KMS)
  - `/runtime/utils` - Shared utilities for runtime tests

- `/terraform` - Contains static analysis tests using [Fugue Regula](https://github.com/fugue/regula)

  - `/terraform/aws` - AWS service-specific Terraform configurations
  - `/terraform/gcp` - GCP service-specific Terraform configurations

- `/cli` - Command-line interface implementation

## Contributing

We welcome contributions from the community! To contribute to Starchitect-CloudGuard, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Make your changes and write tests.
4. Submit a pull request.
5. Await review and approval.

For more details, refer to the [Contributing Guide](CONTRIBUTING.md).

The Starchitect-CloudGuard community is vibrant and collaborative. Join us on our [Discord server](https://discord.gg/kDTtfpgFFq) to connect, ask questions, share insights, and contribute to the project.

## FAQ

1. Why are you using the Commons Clause licence?

   We have chosen to use the [Commons Clause](https://commonsclause.com/) license for this project in order to strike a balance between open source values and sustainability. Our goal is to ensure that the software remains freely available for everyone to use, modify, and share, while also protecting our ability to further develop and maintain the project.

   The Commons Clause is a license condition that can be added to existing open source licenses like the Apache, MIT or GPL licenses. When applied, the Commons Clause allows free use, modification, and sharing of the software, but prohibits others from selling the software or offering it as part of a commercial hosted service without explicit permission.

   We believe this approach has several benefits:

   - **Free for all users:** The software remains free forever for anyone to use, whether you're an individual, non-profit, startup, or large enterprise. You can use it in your own projects, modify it to suit your needs, and share it with others, as long as you comply with the terms of the open source license.

   - **Protects project sustainability:** By prohibiting unauthorized commercial resale of the software, the Commons Clause ensures that the original developers and maintainers can sustain the development of the project. Without this, there is a risk that third parties could take the software, resell it, and capture the value without contributing back.

   - **Allows commercial licensing:** For companies that wish to sell the software commercially or offer it as a paid hosted service, the Commons Clause allows for the negotiation of commercial licenses. This ensures the project can be monetized where appropriate to fund ongoing development.

   We understand some may have concerns about the Commons Clause and its impact on open source. However, we believe this balanced approach is currently the best way to make the software as widely available as possible while ensuring the long-term sustainability and success of the project. The Commons Clause provides the legal teeth to enforce these terms.

   If you have any other questions or concerns about the licensing, please don't hesitate to reach out. We believe in being fully transparent about our choice of license and how it impacts the community. Our aim is to create amazing software that empowers users while building a sustainable open source project.
