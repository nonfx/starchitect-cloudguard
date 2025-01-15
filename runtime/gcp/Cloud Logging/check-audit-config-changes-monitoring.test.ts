// @ts-nocheck
import { MonitoringClient } from '@google-cloud/monitoring';
import { LoggingClient } from '@google-cloud/logging';
import { ComplianceStatus } from '../../types.js';
import checkAuditConfigChangesMonitoring from './check-audit-config-changes-monitoring';

// Mock GCP clients
jest.mock('@google-cloud/monitoring');
jest.mock('@google-cloud/logging');

describe('checkAuditConfigChangesMonitoring', () => {
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
        it('should return PASS when valid metric filter and alert policy exist', async () => {
            const validMetric = {
                filter: 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
            };

            const validAlertPolicy = {
                conditions: [{
                    conditionThreshold: {
                        comparison: 'COMPARISON_GT',
                        thresholdValue: 0,
                        duration: {
                            seconds: 0,
                            nanos: 0
                        }
                    }
                }]
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[validAlertPolicy]]);

            const result = await checkAuditConfigChangesMonitoring('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].message).toContain('Valid metric filter and alert policy found');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when metric filter is missing', async () => {
            mockListMetrics.mockResolvedValue([[]]);
            mockListAlertPolicies.mockResolvedValue([[{}]]);

            const result = await checkAuditConfigChangesMonitoring('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No metric filter found');
        });

        it('should return FAIL when alert policy is invalid', async () => {
            const validMetric = {
                filter: 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
            };

            const invalidAlertPolicy = {
                conditions: [{
                    conditionThreshold: {
                        comparison: 'COMPARISON_LT',
                        thresholdValue: 1
                    }
                }]
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[invalidAlertPolicy]]);

            const result = await checkAuditConfigChangesMonitoring('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No valid alert policy found');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when logging API call fails', async () => {
            mockListMetrics.mockRejectedValue(new Error('API Error'));

            const result = await checkAuditConfigChangesMonitoring('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking audit config monitoring');
        });

        it('should return ERROR when monitoring API call fails', async () => {
            const validMetric = {
                filter: 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockRejectedValue(new Error('API Error'));

            const result = await checkAuditConfigChangesMonitoring('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking audit config monitoring');
        });
    });

    describe('Edge Cases', () => {
        it('should handle empty alert policies response', async () => {
            const validMetric = {
                filter: 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkAuditConfigChangesMonitoring('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No valid alert policy found');
        });

        it('should handle null or undefined conditions in alert policies', async () => {
            const validMetric = {
                filter: 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
            };

            const invalidAlertPolicy = {
                conditions: null
            };

            mockListMetrics.mockResolvedValue([[validMetric]]);
            mockListAlertPolicies.mockResolvedValue([[invalidAlertPolicy]]);

            const result = await checkAuditConfigChangesMonitoring('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No valid alert policy found');
        });
    });
});