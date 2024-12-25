import { CloudWatchLogsClient, DescribeMetricFiltersCommand } from '@aws-sdk/client-cloudwatch-logs';
import { CloudTrailClient, DescribeTrailsCommand } from '@aws-sdk/client-cloudtrail';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from "~runtime/types";
import checkSecurityGroupMonitoring from './aws_cloudwatch_security_group';

const mockCloudWatchLogsClient = mockClient(CloudWatchLogsClient);
const mockCloudTrailClient = mockClient(CloudTrailClient);

const validTrail = {
    Name: 'test-trail',
    IsMultiRegionTrail: true,
    CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:test-group:*',
    CloudWatchLogsRoleArn: 'arn:aws:iam::123456789012:role/CloudTrailRole'
};

const securityGroupMetricFilter = {
    filterName: 'SecurityGroupChanges',
    filterPattern: '{ ($.eventName = AuthorizeSecurityGroupIngress) || ' +
        '($.eventName = AuthorizeSecurityGroupEgress) || ' +
        '($.eventName = RevokeSecurityGroupIngress) || ' +
        '($.eventName = RevokeSecurityGroupEgress) || ' +
        '($.eventName = CreateSecurityGroup) || ' +
        '($.eventName = DeleteSecurityGroup) }'
};

describe('checkSecurityGroupMonitoring', () => {
    beforeEach(() => {
        mockCloudWatchLogsClient.reset();
        mockCloudTrailClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when security group monitoring is properly configured', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [validTrail]
            });

            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
                metricFilters: [securityGroupMetricFilter]
            });

            const result = await checkSecurityGroupMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].message).toBe('Security group changes are being monitored');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when no CloudTrail trails exist', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: []
            });

            const result = await checkSecurityGroupMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No CloudTrail trails configured');
        });

        it('should return FAIL when CloudTrail is not properly configured', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [{
                    Name: 'invalid-trail',
                    IsMultiRegionTrail: false
                }]
            });

            const result = await checkSecurityGroupMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No properly configured CloudTrail found with CloudWatch Logs integration');
        });

        it('should return FAIL when no security group metric filter exists', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [validTrail]
            });

            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).resolves({
                metricFilters: []
            });

            const result = await checkSecurityGroupMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No metric filter found for security group changes');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when CloudTrail API call fails', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error('CloudTrail API Error'));

            const result = await checkSecurityGroupMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('CloudTrail API Error');
        });

        it('should return ERROR when CloudWatch Logs API call fails', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [validTrail]
            });

            mockCloudWatchLogsClient.on(DescribeMetricFiltersCommand).rejects(new Error('CloudWatch Logs API Error'));

            const result = await checkSecurityGroupMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('CloudWatch Logs API Error');
        });
    });
});