import { CloudTrailClient, DescribeTrailsCommand } from '@aws-sdk/client-cloudtrail';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '@codegen/utils/stringUtils';
import checkCloudTrailEnabled from './check-cloudtrail-enabled';

const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockEnabledMultiRegionTrail = {
    Name: 'enabled-multi-region-trail',
    TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/enabled-multi-region-trail',
    IsMultiRegionTrail: true,
    IsLogging: true
};

const mockDisabledTrail = {
    Name: 'disabled-trail',
    TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/disabled-trail',
    IsMultiRegionTrail: true,
    IsLogging: false
};

const mockSingleRegionTrail = {
    Name: 'single-region-trail',
    TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/single-region-trail',
    IsMultiRegionTrail: false,
    IsLogging: true
};

describe('checkCloudTrailEnabled', () => {
    beforeEach(() => {
        mockCloudTrailClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when multi-region trail is enabled', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [mockEnabledMultiRegionTrail]
            });

            const result = await checkCloudTrailEnabled();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('enabled-multi-region-trail');
            expect(result.checks[0].resourceArn).toBe(mockEnabledMultiRegionTrail.TrailARN);
        });

        it('should return PASS for enabled multi-region trail among multiple trails', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [mockDisabledTrail, mockEnabledMultiRegionTrail, mockSingleRegionTrail]
            });

            const result = await checkCloudTrailEnabled();
            expect(result.checks.some(check => check.status === ComplianceStatus.PASS)).toBeTruthy();
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when no trails exist', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: []
            });

            const result = await checkCloudTrailEnabled();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No CloudTrail trails found in the account');
        });

        it('should return FAIL for disabled trails', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [mockDisabledTrail]
            });

            const result = await checkCloudTrailEnabled();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('Trail logging is not enabled');
        });

        it('should return FAIL for single-region trails', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [mockSingleRegionTrail]
            });

            const result = await checkCloudTrailEnabled();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('Trail is not multi-region');
        });

        it('should handle trails without name or ARN', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({
                trailList: [{ IsMultiRegionTrail: true, IsLogging: true }]
            });

            const result = await checkCloudTrailEnabled();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Trail found without name or ARN');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API call fails', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).rejects(new Error('API Error'));

            const result = await checkCloudTrailEnabled();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Error checking CloudTrail trails: API Error');
        });

        it('should handle undefined trailList', async () => {
            mockCloudTrailClient.on(DescribeTrailsCommand).resolves({});

            const result = await checkCloudTrailEnabled();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No CloudTrail trails found in the account');
        });
    });
});