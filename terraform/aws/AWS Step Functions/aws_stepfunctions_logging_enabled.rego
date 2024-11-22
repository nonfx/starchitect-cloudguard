package rules.stepfunctions_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "StepFunctions.1",
	"title": "Step Functions state machines should have logging turned on",
	"description": "AWS Step Functions state machines must enable logging for monitoring execution history and debugging multi-point failures.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_StepFunctions.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Step Functions state machines
state_machines = fugue.resources("aws_sfn_state_machine")

# Helper to check if logging is properly configured
has_logging_enabled(machine) {
	machine.logging_configuration != null
	machine.logging_configuration[_].level != null
	machine.logging_configuration[_].include_execution_data == true
	machine.logging_configuration[_].log_destination != null
}

# Allow if logging is properly configured
policy[p] {
	machine := state_machines[_]
	has_logging_enabled(machine)
	p = fugue.allow_resource(machine)
}

# Deny if logging is not properly configured
policy[p] {
	machine := state_machines[_]
	not has_logging_enabled(machine)
	p = fugue.deny_resource_with_message(machine, "Step Functions state machine must have logging enabled with appropriate configuration including execution data and log destination.")
}
