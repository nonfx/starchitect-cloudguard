import { ConfigServiceClient, DescribeConfigurationAggregatorsCommand } from "@aws-sdk/client-config-service";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkConfigEnabledAllRegions from "./check-config-enabled-all-regions";

const mockConfigClient = mockClient(ConfigServiceClient);

describe("checkConfigEnabledAllRegions", () => {
    beforeEach(() => {
        mockConfigClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when account aggregation is enabled for all regions", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).resolves({
                ConfigurationAggregators: [{
                    ConfigurationAggregatorName: "test-aggregator",
                    AccountAggregationSources: [{
                        AllRegions: true,
                        AccountIds: ["123456789012"]
                    }]
                }]
            });

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-aggregator");
            expect(result.checks[0].message).toBe("Config aggregator is properly configured for all regions");
        });

        it("should return PASS when organization aggregation is enabled for all regions", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).resolves({
                ConfigurationAggregators: [{
                    ConfigurationAggregatorName: "org-aggregator",
                    OrganizationAggregationSource: {
                        AllRegions: true,
                        RoleArn: "arn:aws:iam::123456789012:role/service-role/config-role"
                    }
                }]
            });

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("org-aggregator");
        });

        it("should handle multiple compliant aggregators", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).resolves({
                ConfigurationAggregators: [
                    {
                        ConfigurationAggregatorName: "account-aggregator",
                        AccountAggregationSources: [{ AllRegions: true }]
                    },
                    {
                        ConfigurationAggregatorName: "org-aggregator",
                        OrganizationAggregationSource: { AllRegions: true }
                    }
                ]
            });

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when no aggregators exist", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).resolves({
                ConfigurationAggregators: []
            });

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No configuration aggregators found. AWS Config might not be enabled.");
        });

        it("should return FAIL when aggregator is not configured for all regions", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).resolves({
                ConfigurationAggregators: [{
                    ConfigurationAggregatorName: "partial-aggregator",
                    AccountAggregationSources: [{
                        AllRegions: false,
                        Regions: ["us-east-1", "us-west-2"]
                    }]
                }]
            });

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Config aggregator is not configured to collect data from all regions");
        });

        it("should handle mixed compliance scenarios", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).resolves({
                ConfigurationAggregators: [
                    {
                        ConfigurationAggregatorName: "compliant-aggregator",
                        AccountAggregationSources: [{ AllRegions: true }]
                    },
                    {
                        ConfigurationAggregatorName: "non-compliant-aggregator",
                        AccountAggregationSources: [{ AllRegions: false }]
                    }
                ]
            });

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).rejects(
                new Error("API Error")
            );

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking AWS Config: API Error");
        });

        it("should handle undefined aggregator name", async () => {
            mockConfigClient.on(DescribeConfigurationAggregatorsCommand).resolves({
                ConfigurationAggregators: [{
                    AccountAggregationSources: [{ AllRegions: true }]
                }]
            });

            const result = await checkConfigEnabledAllRegions();
            expect(result.checks[0].resourceName).toBe("Unknown Aggregator");
        });
    });
});