// @ts-nocheck
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
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEncryptedCommunications from "./check-encrypted-communications";

const mockSimSpaceClient = mockClient(SimSpaceWeaverClient);
const mockCloudFrontClient = mockClient(CloudFrontClient);
const mockELBv2Client = mockClient(ElasticLoadBalancingV2Client);

const mockDistribution = {
	Id: "DIST123",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST123"
};

const mockLoadBalancer = {
	LoadBalancerArn:
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-lb/1234567890"
};

const mockSimulation = {
	Arn: "arn:aws:simspaceweaver:us-east-1:123456789012:simulation/test-sim"
};

describe("checkEncryptedCommunications", () => {
	beforeEach(() => {
		mockSimSpaceClient.reset();
		mockCloudFrontClient.reset();
		mockELBv2Client.reset();

		// Default mock for SimSpace Weaver to have simulations
		mockSimSpaceClient.on(ListSimulationsCommand).resolves({ Simulations: [mockSimulation] });
	});

	describe("No SimSpace Weaver Resources", () => {
		it("should return NOTAPPLICABLE when no simulations exist", async () => {
			mockSimSpaceClient.on(ListSimulationsCommand).resolves({ Simulations: [] });

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No SimSpace Weaver simulations found");
		});
	});

	describe("Compliant Resources", () => {
		it("should return PASS for properly encrypted CloudFront distribution", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({
					DistributionList: {
						Items: [mockDistribution]
					}
				})
				.on(GetDistributionCommand)
				.resolves({
					Distribution: {
						DistributionConfig: {
							DefaultCacheBehavior: {
								ViewerProtocolPolicy: "https-only"
							},
							ViewerCertificate: {
								ACMCertificateArn:
									"arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
							}
						}
					}
				});

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toContain("DIST123");
		});

		it("should return PASS for HTTPS ALB listener", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [] } });

			mockELBv2Client
				.on(DescribeLoadBalancersCommand)
				.resolves({
					LoadBalancers: [mockLoadBalancer]
				})
				.on(DescribeListenersCommand)
				.resolves({
					Listeners: [
						{
							Protocol: "HTTPS",
							ListenerArn:
								"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-lb/1234567890/abcdef"
						}
					]
				});

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for CloudFront distribution without HTTPS", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({
					DistributionList: {
						Items: [mockDistribution]
					}
				})
				.on(GetDistributionCommand)
				.resolves({
					Distribution: {
						DistributionConfig: {
							DefaultCacheBehavior: {
								ViewerProtocolPolicy: "allow-all"
							},
							ViewerCertificate: {}
						}
					}
				});

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Distribution is not properly configured for HTTPS");
		});

		it("should return FAIL for HTTP-only ALB listener", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [] } });

			mockELBv2Client
				.on(DescribeLoadBalancersCommand)
				.resolves({
					LoadBalancers: [mockLoadBalancer]
				})
				.on(DescribeListenersCommand)
				.resolves({
					Listeners: [
						{
							Protocol: "HTTP",
							ListenerArn:
								"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-lb/1234567890/abcdef"
						}
					]
				});

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Listener is not using encrypted protocol (HTTPS/TLS)");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when SimSpace Weaver API fails", async () => {
			mockSimSpaceClient.on(ListSimulationsCommand).rejects(new Error("SimSpace Weaver API error"));

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("SimSpace Weaver API error");
		});

		it("should return ERROR when CloudFront API fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("CloudFront API error"));

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("CloudFront API error");
		});

		it("should return ERROR when ELB API fails", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [] } });

			mockELBv2Client.on(DescribeLoadBalancersCommand).rejects(new Error("ELB API error"));

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("ELB API error");
		});
	});

	describe("Edge Cases", () => {
		it("should handle no distributions or load balancers", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [] } });

			mockELBv2Client.on(DescribeLoadBalancersCommand).resolves({ LoadBalancers: [] });

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks).toHaveLength(0);
		});

		it("should handle mixed protocol listeners", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [] } });

			mockELBv2Client
				.on(DescribeLoadBalancersCommand)
				.resolves({
					LoadBalancers: [mockLoadBalancer]
				})
				.on(DescribeListenersCommand)
				.resolves({
					Listeners: [
						{ Protocol: "HTTPS", ListenerArn: "arn:aws:elasticloadbalancing:listener1" },
						{ Protocol: "HTTP", ListenerArn: "arn:aws:elasticloadbalancing:listener2" }
					]
				});

			const result = await checkEncryptedCommunications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
