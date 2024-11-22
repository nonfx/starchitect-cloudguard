package rules.aws_account_part_of_organizations

import data.fugue

__rego__metadoc__ := {
	"id": "Account.2",
	"title": "AWS accounts should be part of an AWS Organizations organization",
	"description": "This control checks if an AWS account is part of an organization managed through AWS Organizations. The control fails if the account is not part of an organization.Organizations helps you centrally manage your environment as you scale your workloads on AWS. You can use multiple AWS accounts to isolate workloads that have specific security requirements, or to comply with frameworks such as HIPAA or PCI. By creating an organization, you can administer multiple accounts as a single unit and centrally manage their access to AWS services, resources, and Regions",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Account.2"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_accounts := fugue.resources("aws_account")

is_part_of_organization(account) {
	account.organization_id != null
	account.organization_id != ""
}

policy[p] {
	account := aws_accounts[_]
	is_part_of_organization(account)
	p = fugue.allow_resource(account)
}

policy[p] {
	account := aws_accounts[_]
	not is_part_of_organization(account)
	p = fugue.deny_resource_with_message(account, "AWS account is not part of an AWS Organizations organization")
}
