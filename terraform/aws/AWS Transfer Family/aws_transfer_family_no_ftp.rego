package rules.transfer_family_no_ftp

import data.fugue

__rego__metadoc__ := {
	"id": "Transfer.2",
	"title": "Transfer Family servers should not use FTP protocol for endpoint connection",
	"description": "AWS Transfer Family servers must avoid FTP protocol for secure endpoint connections to prevent data interception risks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Transfer.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Transfer Family servers
transfer_servers = fugue.resources("aws_transfer_server")

# Helper to check if server uses FTP protocol
uses_ftp(server) {
	server.protocols[_] == "FTP"
}

# Allow if server doesn't use FTP
policy[p] {
	server := transfer_servers[_]
	not uses_ftp(server)
	p = fugue.allow_resource(server)
}

# Deny if server uses FTP
policy[p] {
	server := transfer_servers[_]
	uses_ftp(server)
	p = fugue.deny_resource_with_message(server, "Transfer Family server must not use FTP protocol. Use SFTP, FTPS, or AS2 instead for secure data transfer.")
}
