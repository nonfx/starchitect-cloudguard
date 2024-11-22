package rules.ssm_documents_not_public

import data.fugue

__rego__metadoc__ := {
	"id": "SSM.4",
	"title": "SSM documents should not be public",
	"description": "SSM documents owned by the account should not be public to prevent unauthorized access and protect sensitive information about AWS resources.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_SSM.4"]},"severity":"Critical","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SSM documents
ssm_documents = fugue.resources("aws_ssm_document")

# Helper to check if document is public
is_public(doc) {
	doc.permissions.account_ids[_] == "All"
}

# Allow if document is not public
policy[p] {
	doc := ssm_documents[_]
	not is_public(doc)
	p = fugue.allow_resource(doc)
}

# Deny if document is public
policy[p] {
	doc := ssm_documents[_]
	is_public(doc)
	p = fugue.deny_resource_with_message(doc, "SSM document should not be public. Remove public permissions to protect sensitive information.")
}
