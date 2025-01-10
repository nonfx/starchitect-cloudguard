import { SimSpaceWeaverClient, ListSimulationsCommand } from "@aws-sdk/client-simspaceweaver";
import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import {
	ElasticLoadBalancingV2Client,
	DescribeLoadBalancersCommand,
	DescribeListenersCommand
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";

async function checkEncryptedCommunications(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// First check if any SimSpace Weaver simulations exist
		const simSpaceClient = new SimSpaceWeaverClient({ region });
		const simulations = await simSpaceClient.send(new ListSimulationsCommand({}));

		if (!simulations.Simulations?.length) {
			results.checks = [
				{
					resourceName: "No SimSpace Weaver Simulations",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No SimSpace Weaver simulations found"
				}
			];
			return results;
		}

		// Check CloudFront distributions
		const cloudFrontClient = new CloudFrontClient({ region });
		const distributions = await cloudFrontClient.send(new ListDistributionsCommand({}));

		if (distributions.DistributionList?.Items) {
			for (const distribution of distributions.DistributionList.Items) {
				if (!distribution.Id) continue;

				const distConfig = await cloudFrontClient.send(
					new GetDistributionCommand({ Id: distribution.Id })
				);

				const viewerProtocolPolicy =
					distConfig.Distribution?.DistributionConfig?.DefaultCacheBehavior?.ViewerProtocolPolicy;
				const hasValidCert =
					distConfig.Distribution?.DistributionConfig?.ViewerCertificate?.ACMCertificateArn ||
					distConfig.Distribution?.DistributionConfig?.ViewerCertificate?.IAMCertificateId ||
					distConfig.Distribution?.DistributionConfig?.ViewerCertificate
						?.CloudFrontDefaultCertificate;

				const isEncrypted =
					viewerProtocolPolicy === "redirect-to-https" || viewerProtocolPolicy === "https-only";

				results.checks.push({
					resourceName: `CloudFront Distribution ${distribution.Id}`,
					resourceArn: distribution.ARN,
					status: isEncrypted && hasValidCert ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						isEncrypted && hasValidCert
							? undefined
							: "Distribution is not properly configured for HTTPS"
				});
			}
		}

		// Check ALB listeners
		const elbClient = new ElasticLoadBalancingV2Client({ region });
		const loadBalancers = await elbClient.send(new DescribeLoadBalancersCommand({}));

		if (loadBalancers.LoadBalancers) {
			for (const lb of loadBalancers.LoadBalancers) {
				if (!lb.LoadBalancerArn) continue;

				const listeners = await elbClient.send(
					new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn })
				);

				if (listeners.Listeners) {
					for (const listener of listeners.Listeners) {
						const isEncrypted = listener.Protocol === "HTTPS" || listener.Protocol === "TLS";

						results.checks.push({
							resourceName: `ALB Listener ${listener.ListenerArn}`,
							resourceArn: listener.ListenerArn,
							status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
							message: isEncrypted
								? undefined
								: "Listener is not using encrypted protocol (HTTPS/TLS)"
						});
					}
				}
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Encryption Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking encryption: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkEncryptedCommunications(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "SimSpace Weaver",
	shortServiceName: "simspaceweaver",
	title: "Ensure communications between your applications and clients is encrypted",
	description:
		"There is no setting for encryption setup for your clients and applications within SimSpace Weaver service. For this audit you have to confirm that the communication is configured in the app and the client with encryption to protect that traffic.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_11.1",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEncryptedCommunications
} satisfies RuntimeTest;
