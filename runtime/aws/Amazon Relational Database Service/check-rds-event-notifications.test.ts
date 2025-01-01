// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	RDSClient,
	DescribeEventSubscriptionsCommand,
	DescribeDBInstancesCommand
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkRdsEventNotifications from "./check-rds-event-notifications";

const mockRdsClient = mockClient(RDSClient);

const mockCompliantInstanceSubscription = {
	CustSubscriptionId: "test-instance-sub",
	SourceType: "db-instance",
	Enabled: true,
	EventCategoriesList: ["maintenance", "configuration change", "failure"],
	SourceIdsList: ["test-db-1"]
};

const mockCompliantClusterSubscription = {
	CustSubscriptionId: "test-cluster-sub",
	SourceType: "db-cluster",
	Enabled: true,
	EventCategoriesList: ["maintenance", "configuration change", "failure"],
	SourceIdsList: ["test-cluster-1"]
};

const mockDbInstance = {
	DBInstanceIdentifier: "test-db-1",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-1"
};

const mockClusterDbInstance = {
	DBInstanceIdentifier: "test-db-2",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-db-2",
	DBClusterIdentifier: "test-cluster-1"
};

describe("checkRdsEventNotifications", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for instance with compliant instance-level subscription", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockCompliantInstanceSubscription]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockDbInstance]
			});

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-db-1");
		});

		it("should return PASS for instance with compliant cluster-level subscription", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockCompliantClusterSubscription]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockClusterDbInstance]
			});

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-db-2");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no subscriptions exist", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: []
			});

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No RDS event subscriptions found");
		});

		it("should return FAIL for instance without matching subscription", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockCompliantInstanceSubscription]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					{
						...mockDbInstance,
						DBInstanceIdentifier: "unmonitored-db"
					}
				]
			});

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"No compliant instance-level event subscription found"
			);
		});

		it("should return FAIL for cluster instance without matching subscription", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockCompliantClusterSubscription]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [
					{
						...mockClusterDbInstance,
						DBClusterIdentifier: "unmonitored-cluster"
					}
				]
			});

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"No compliant cluster-level event subscription found"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when event subscriptions API call fails", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).rejects(new Error("API Error"));

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking RDS event subscriptions: API Error");
		});

		it("should return ERROR when DB instances API call fails", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockCompliantInstanceSubscription]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: undefined
			});

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve RDS instances");
		});

		it("should handle subscriptions without CustSubscriptionId", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [
					{
						...mockCompliantInstanceSubscription,
						CustSubscriptionId: undefined
					}
				]
			});
			mockRdsClient.on(DescribeDBInstancesCommand).resolves({
				DBInstances: [mockDbInstance]
			});

			const result = await checkRdsEventNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
