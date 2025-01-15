// @ts-nocheck
import { MonitoringClient } from '@google-cloud/monitoring';
import { LoggingClient } from '@google-cloud/logging';
import { ComplianceStatus } from '../../types.js';
import checkProjectOwnershipMonitoring from './check-project-ownership-monitoring';

// Mock GCP clients
jest.mock('@google-cloud/monitoring');
jest.mock('@google-cloud/logging');

describe('checkProjectOwnershipMonitoring', () => {
    const mockGetMetrics = jest.fn();
    const mockListAlertPolicies = jest.fn();
    const projectId = 'test-project';

    beforeEach(() => {
        jest.resetAllMocks();
        
        // Setup LoggingClient mock
        (LoggingClient as jest.Mock).mockImplementation(() => ({
            getMetrics: mockGetMetrics
        }));

        // Setup MonitoringClient mock
        (MonitoringClient as jest.Mock).mockImplementation(() => ({
            listAlertPolicies: mockListAlertPolicies
        }));
    });

    describe('Compliant Resources', () => {
        it('should return PASS when both metric filter and alert policy exist', async () => {
            const validMetric = {
                name: 'projects/test-project/metrics/project_ownership_changes',
                filter: 'resource.type = "project" AND protopayload.serviceName = "cloudresourcemanager.googleapis.com" AND protopayload.methodName = ("SetIamPolicy" OR "setIamPolicy") AND protopayload.serviceData.policyDelta.bindingDeltas.action = ("ADD" OR "REMOVE") AND protopayload.serviceData.policyDelta.bindingDeltas.role = "roles/owner"'
            };

            const validAlertPolicy = {
                name: 'projects/test-project/alertPolicies/ownership-alert',
                conditions: [{
                    conditionThreshold: {
                        filter: 'metric.type = "logging.googleapis.com/user/project_ownership_changes"'
                    }
                }]
            };

            mockGetMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[validAlertPolicy]]);

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when metric filter is missing', async () => {
            mockGetMetrics.mockResolvedValue([[]]);
            mockListAlertPolicies.mockResolvedValue([[{
                name: 'test-alert',
                conditions: [{
                    conditionThreshold: {
                        filter: 'metric.type = "logging.googleapis.com/user/project_ownership_changes"'
                    }
                }]
            }]]);

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No valid log metric filter found');
        });

        it('should return FAIL when alert policy is missing', async () => {
            const validMetric = {
                name: 'test-metric',
                filter: 'resource.type = "project" AND protopayload.serviceName = "cloudresourcemanager.googleapis.com"'
            };

            mockGetMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[1].message).toContain('No alert policy found');
        });

        it('should return FAIL when metric filter has incorrect components', async () => {
            const invalidMetric = {
                name: 'test-metric',
                filter: 'resource.type = "project"' // Missing required components
            };

            mockGetMetrics.mockResolvedValue([[invalidMetric]]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when getMetrics fails', async () => {
            mockGetMetrics.mockRejectedValue(new Error('API Error'));

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking project ownership monitoring');
        });

        it('should return ERROR when listAlertPolicies fails', async () => {
            mockGetMetrics.mockResolvedValue([[]]);
            mockListAlertPolicies.mockRejectedValue(new Error('API Error'));

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
        });
    });

    describe('Edge Cases', () => {
        it('should handle empty responses from both APIs', async () => {
            mockGetMetrics.mockResolvedValue([[]]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.FAIL)).toBe(true);
        });

        it('should handle undefined filter in metric', async () => {
            mockGetMetrics.mockResolvedValue([[{ name: 'test-metric' }]]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkProjectOwnershipMonitoring(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });
});