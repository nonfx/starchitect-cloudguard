// @ts-nocheck
import { MonitoringClient } from '@google-cloud/monitoring';
import { LoggingClient } from '@google-cloud/logging';
import { ComplianceStatus } from '../../types.js';
import checkVpcFirewallRuleChanges from './check-vpc-firewall-rule-changes';

// Mock GCP clients
jest.mock('@google-cloud/monitoring');
jest.mock('@google-cloud/logging');

describe('checkVpcFirewallRuleChanges', () => {
    const mockProjectId = 'test-project';
    let mockGetMetrics;
    let mockListAlertPolicies;

    beforeEach(() => {
        jest.resetAllMocks();
        
        // Setup LoggingClient mock
        mockGetMetrics = jest.fn();
        (LoggingClient as jest.Mock).mockImplementation(() => ({
            getMetrics: mockGetMetrics
        }));

        // Setup MonitoringClient mock
        mockListAlertPolicies = jest.fn();
        (MonitoringClient as jest.Mock).mockImplementation(() => ({
            listAlertPolicies: mockListAlertPolicies
        }));
    });

    describe('Compliant Resources', () => {
        it('should return PASS when valid metric filter and alert policy exist', async () => {
            // Mock valid metric filter
            mockGetMetrics.mockResolvedValue([[{
                filter: 'resource.type="gce_firewall_rule" AND methodName="compute.firewalls.patch"'
            }]]);

            // Mock valid alert policy
            mockListAlertPolicies.mockResolvedValue([[{
                conditions: [{
                    conditionThreshold: {
                        comparison: 'COMPARISON_GT',
                        thresholdValue: 0,
                        duration: { seconds: 0 }
                    }
                }]
            }]]);

            const result = await checkVpcFirewallRuleChanges.execute(mockProjectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('VPC Firewall Rule Monitoring');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when metric filter is missing', async () => {
            mockGetMetrics.mockResolvedValue([[{
                filter: 'resource.type="other_resource"'
            }]]);

            const result = await checkVpcFirewallRuleChanges.execute(mockProjectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No valid metric filter found');
        });

        it('should return FAIL when alert policy is missing', async () => {
            mockGetMetrics.mockResolvedValue([[{
                filter: 'resource.type="gce_firewall_rule" AND methodName="compute.firewalls.patch"'
            }]]);

            mockListAlertPolicies.mockResolvedValue([[{
                conditions: [{
                    conditionThreshold: {
                        comparison: 'COMPARISON_LT',
                        thresholdValue: 1,
                        duration: { seconds: 300 }
                    }
                }]
            }]]);

            const result = await checkVpcFirewallRuleChanges.execute(mockProjectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No valid alert policy found');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when metrics API call fails', async () => {
            mockGetMetrics.mockRejectedValue(new Error('API Error'));

            const result = await checkVpcFirewallRuleChanges.execute(mockProjectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking firewall rule monitoring');
        });

        it('should return ERROR when alert policies API call fails', async () => {
            mockGetMetrics.mockResolvedValue([[{
                filter: 'resource.type="gce_firewall_rule" AND methodName="compute.firewalls.patch"'
            }]]);
            
            mockListAlertPolicies.mockRejectedValue(new Error('API Error'));

            const result = await checkVpcFirewallRuleChanges.execute(mockProjectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking firewall rule monitoring');
        });
    });

    describe('Edge Cases', () => {
        it('should handle empty metrics response', async () => {
            mockGetMetrics.mockResolvedValue([[]]);

            const result = await checkVpcFirewallRuleChanges.execute(mockProjectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });

        it('should handle empty alert policies response', async () => {
            mockGetMetrics.mockResolvedValue([[{
                filter: 'resource.type="gce_firewall_rule" AND methodName="compute.firewalls.patch"'
            }]]);
            
            mockListAlertPolicies.mockResolvedValue([[]]);

            const result = await checkVpcFirewallRuleChanges.execute(mockProjectId);
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });
});