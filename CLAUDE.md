# Starchitect CloudGuard

Cloud security compliance policies and runtime checks for AWS and GCP.

## Project Structure

```
starchitect-cloudguard/
├── terraform/              # OPA/Rego security policies (IaC scanning)
│   ├── aws/               # AWS policies (66 service categories)
│   └── gcp/               # GCP policies (11 service categories)
├── runtime/               # TypeScript runtime checks (live cloud API)
│   ├── aws/               # AWS runtime checks with tests
│   └── gcp/               # GCP runtime checks with tests
├── cli/                   # CLI application (oclif-based)
└── .scripts/              # Build and test scripts
```

## OPA/Rego Policies

Located in `terraform/aws/` and `terraform/gcp/`. Each policy directory contains:

- `*.rego` - Policy file using Fugue/Regula framework
- `*_pass.tf` - Terraform fixture that should pass the policy
- `*_fail.tf` - Terraform fixture that should fail the policy

### Running OPA Tests

```bash
# Run all OPA tests
npm run test:opa

# Run with verbose output
npm run test:opa:verbose

# Filter to specific policies
bun ./.scripts/run-opa-tests.ts --filter "AWS Lambda"
bun ./.scripts/run-opa-tests.ts --filter gcp
```

Uses `regula-wasi` (nonfx fork with OPA v1.12.2) to evaluate policies against test fixtures.

## Runtime Tests

TypeScript tests in `runtime/` use BUN test runner with Jest-style syntax:

```bash
# Run all runtime tests
npm test
# or
bun test
```

## Commands

| Command            | Description                  |
| ------------------ | ---------------------------- |
| `npm test`         | Run runtime tests (bun test) |
| `npm run test:opa` | Run OPA/Rego policy tests    |
| `npm run build`    | TypeScript compilation       |
| `npm run lint`     | Run ESLint                   |
| `npm run prettify` | Format code with Prettier    |

## Writing Policies

Rego policies use the Fugue framework:

```rego
package rules.example_policy

import data.fugue

__rego__metadoc__ := {
    "id": "EXAMPLE.1",
    "title": "Example policy title",
    "description": "Description of what this policy checks",
    "custom": {"severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

resources = fugue.resources("aws_example_resource")

policy[p] {
    resource := resources[_]
    # check passes
    p = fugue.allow_resource(resource)
}

policy[p] {
    resource := resources[_]
    # check fails
    p = fugue.deny_resource_with_message(resource, "Error message")
}
```

## Dependencies

- **regula-wasi**: OPA/Rego policy evaluation (WASI build with OPA v1.12.2)
- **bun**: Test runner and TypeScript execution
- **AWS SDK v3**: For runtime checks and test mocking
- **Google Cloud clients**: For GCP runtime checks
