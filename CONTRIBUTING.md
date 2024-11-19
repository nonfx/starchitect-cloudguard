# Contributing to Starchitect-CloudGuard

Thank you for your interest in enhancing Starchitect-CloudGuard! We aim to make the contribution process straightforward and valuable for everyone involved.

## Ways to Contribute

- Submit new security rules in Rego format
- Enhance existing rules
- Report security gaps or issues
- Improve documentation
- Share feedback on rule effectiveness

## Development Process

We utilize GitHub for our development workflow. All improvements happen through pull requests.

## Creating Security Rules

When submitting new security rules:

1. Fork the repository and create a branch from `main`
2. Follow our Rego file structure:
```rego
package rules.aws_secure_something

import data.fugue
import data.fugue.resource_view.resource_view_input

__rego__metadoc__ := {
    "id": "AWS_001",
    "title": "Descriptive Rule Title",
    "description": "Detailed explanation of what this rule checks",
    "custom": {
        "severity": "Critical/High/Medium/Low",
        "service": "AWS Service Name",
        "controls": {
            "CIS": ["1.1", "1.2"],
            "NIST": ["AC-1", "AC-2"]
        }
    }
}

resource_type := "aws_something"

default allow := false

allow {
    # Your rule logic here
}
```

3. Include comprehensive test cases in `test.rego` files
4. Submit your pull request with clear documentation

## Rule Requirements

Each security rule should have:

- Unique identifier (e.g., AWS_001)
- Clear title and description
- Severity level
- Applicable cloud service
- Compliance mappings, if available (CIS, NIST, etc.)
- Test cases demonstrating both valid and invalid scenarios


## Issue Reporting

Use GitHub Issues to report bugs or suggest improvements. Include:

- Rule ID (if applicable)
- Expected vs actual behavior
- Infrastructure code sample demonstrating the issue
- Any relevant error messages

## Testing Guidelines

- All rules must include test cases
- Test both compliant and non-compliant scenarios
- Include edge cases
- Verify performance impact

## License

By contributing to Starchitect-CloudGuard, you agree that your contributions will be licensed under the MIT License.

## Getting Help

Join our [Discord community](https://discord.gg/gG3gDm9GmF) for questions and discussions about rule development and security compliance.