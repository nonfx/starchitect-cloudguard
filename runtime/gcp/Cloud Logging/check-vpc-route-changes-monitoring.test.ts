// @ts-nocheck
import { LoggingClient } from '@google-cloud/logging';
import { MonitoringClient } from '@google-cloud/monitoring';
import { ComplianceStatus } from '../../types.js';
import checkVpcRouteChangesMonitoring from './check-vpc-route-changes-monitoring';

// Mock GCP clients
jest.mock('@google-cloud/logging');
jest.mock('@google-cloud/monitoring');

describe('checkVpcRouteChangesMonitoring', () => {
    const mockListMetrics = jest.fn();
    const mockListAlertPolicies = jest.fn();

    beforeEach(() => {
        jest.resetAllMocks();
        
        // Setup LoggingClient mock
        (LoggingClient as jest.Mock).mockImplementation(() => ({
            listMetrics: mockListMetrics
        }));

        // Setup MonitoringClient mock
        (MonitoringClient as jest.Mock).mockImplementation(() => ({
            listAlertPolicies: mockListAlertPolicies
        }));
    });

    describe('Compliant Resources', () => {
        it('should return PASS when proper metric filter and alert exist', async () => {
            const validMetric = {
                name: 'projects/test-project/metrics/vpc-route-changes',
                filter: 'resource.type="gce_route" AND (methodName="compute.routes.delete" OR methodName="compute.routes.insert")'
            };

            const validAlert = {
                conditions: [{
                    conditionThreshold: {
                        filter: 'projects/test-project/metrics/vpc-route-changes'
                    }
                }]
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[validAlert]]);

            const result = await checkVpcRouteChangesMonitoring('test-project');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when no metric filters exist', async () => {
            mockListMetrics.mockResolvedValue([[]]);

            const result = await checkVpcRouteChangesMonitoring('test-project');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No log metric filters found');
        });

        it('should return FAIL when metric exists but no matching alert policy', async () => {
            const validMetric = {
                name: 'projects/test-project/metrics/vpc-route-changes',
                filter: 'resource.type="gce_route" AND (methodName="compute.routes.delete" OR methodName="compute.routes.insert")'
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkVpcRouteChangesMonitoring('test-project');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('Metric filter exists but no alert policy is configured');
        });

        it('should return FAIL when metric filter does not match required pattern', async () => {
            const invalidMetric = {
                name: 'projects/test-project/metrics/invalid-metric',
                filter: 'resource.type="gce_instance"'
            };

            mockListMetrics.mockResolvedValue([[invalidMetric]]);

            const result = await checkVpcRouteChangesMonitoring('test-project');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No metric filter exists for VPC route changes');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when logging API call fails', async () => {
            mockListMetrics.mockRejectedValue(new Error('API Error'));

            const result = await checkVpcRouteChangesMonitoring('test-project');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking VPC route changes monitoring');
        });

        it('should return ERROR when monitoring API call fails', async () => {
            const validMetric = {
                name: 'projects/test-project/metrics/vpc-route-changes',
                filter: 'resource.type="gce_route" AND (methodName="compute.routes.delete" OR methodName="compute.routes.insert")'
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockRejectedValue(new Error('Monitoring API Error'));

            const result = await checkVpcRouteChangesMonitoring('test-project');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking VPC route changes monitoring');
        });
    });

    describe('Edge Cases', () => {
        it('should handle empty project ID', async () => {
            const result = await checkVpcRouteChangesMonitoring('');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
        });

        it('should handle multiple matching metrics', async () => {
            const metrics = [
                {
                    name: 'projects/test-project/metrics/vpc-route-changes-1',
                    filter: 'resource.type="gce_route" AND (methodName="compute.routes.delete" OR methodName="compute.routes.insert")'
                },
                {
                    name: 'projects/test-project/metrics/vpc-route-changes-2',
                    filter: 'resource.type="gce_route" AND (methodName="compute.routes.delete" OR methodName="compute.routes.insert")'
                }
            ];

            mockListMetrics.mockResolvedValue([metrics]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkVpcRouteChangesMonitoring('test-project');
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.FAIL)).toBe(true);
        });
    });
});