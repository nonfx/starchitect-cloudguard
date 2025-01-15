// @ts-nocheck
import { MonitoringClient } from '@google-cloud/monitoring';
import { LoggingClient } from '@google-cloud/logging';
import { ComplianceStatus } from '../../types.js';
import checkSqlInstanceConfigChanges from './check-sql-instance-config-changes';

// Mock GCP clients
jest.mock('@google-cloud/monitoring');
jest.mock('@google-cloud/logging');

describe('checkSqlInstanceConfigChanges', () => {
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
        it('should return PASS when metric filter and alert policy are properly configured', async () => {
            const mockMetric = {
                name: 'sql-config-metric',
                filter: 'resource.type=\"cloudsql_database\" AND protoPayload.methodName=\"cloudsql.instances.update\"'
            };

            const mockAlertPolicy = {
                conditions: [{
                    displayName: 'SQL Instance Configuration Changes',
                    conditionThreshold: {
                        filter: 'sql-config-metric'
                    }
                }]
            };

            mockGetMetrics.mockResolvedValue([[mockMetric]]);
            mockListAlertPolicies.mockResolvedValue([[mockAlertPolicy]]);

            const result = await checkSqlInstanceConfigChanges(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].message).toBe('Metric filter and alert policy are properly configured');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when metric filter is missing', async () => {
            mockGetMetrics.mockResolvedValue([[]]);
            
            const result = await checkSqlInstanceConfigChanges(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No metric filter found for SQL instance configuration changes');
        });

        it('should return FAIL when alert policy is missing', async () => {
            const mockMetric = {
                name: 'sql-config-metric',
                filter: 'resource.type=\"cloudsql_database\" AND protoPayload.methodName=\"cloudsql.instances.update\"'
            };

            mockGetMetrics.mockResolvedValue([[mockMetric]]);
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkSqlInstanceConfigChanges(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No alert policy found for SQL instance configuration changes');
        });

        it('should return FAIL when alert policy has incorrect configuration', async () => {
            const mockMetric = {
                name: 'sql-config-metric',
                filter: 'resource.type=\"cloudsql_database\" AND protoPayload.methodName=\"cloudsql.instances.update\"'
            };

            const mockAlertPolicy = {
                conditions: [{
                    displayName: 'Wrong Display Name',
                    conditionThreshold: {
                        filter: 'wrong-metric'
                    }
                }]
            };

            mockGetMetrics.mockResolvedValue([[mockMetric]]);
            mockListAlertPolicies.mockResolvedValue([[mockAlertPolicy]]);

            const result = await checkSqlInstanceConfigChanges(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('No alert policy found for SQL instance configuration changes');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when getMetrics fails', async () => {
            mockGetMetrics.mockRejectedValue(new Error('API Error'));

            const result = await checkSqlInstanceConfigChanges(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking SQL config change monitoring');
        });

        it('should return ERROR when listAlertPolicies fails', async () => {
            const mockMetric = {
                name: 'sql-config-metric',
                filter: 'resource.type=\"cloudsql_database\" AND protoPayload.methodName=\"cloudsql.instances.update\"'
            };

            mockGetMetrics.mockResolvedValue([[mockMetric]]);
            mockListAlertPolicies.mockRejectedValue(new Error('API Error'));

            const result = await checkSqlInstanceConfigChanges(projectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking SQL config change monitoring');
        });
    });
});