import { IAMClient, ListPoliciesCommand } from "@aws-sdk/client-iam";
export async function getAllIAMPolicies(iamClient: IAMClient) {
	const policies = [];
	let marker: string | undefined;

	do {
		const response = await iamClient.send(
			new ListPoliciesCommand({
				Scope: "Local", // Only customer-managed policies
				OnlyAttached: true, // Only policies attached to IAM users/groups/roles
				Marker: marker
			})
		);

		if (response.Policies) {
			policies.push(...response.Policies);
		}

		marker = response.Marker;
	} while (marker);

	return policies;
}
