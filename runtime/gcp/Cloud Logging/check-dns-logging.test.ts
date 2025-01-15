// @ts-nocheck
import { ComputeClient, DNSClient } from '@google-cloud/compute';
import { ComplianceStatus } from '../../types.js';
import checkDnsLogging from './check-dns-logging';

// Mock GCP clients
jest.mock('@google-cloud/compute', () => ({
    ComputeClient: jest.fn().mockImplementation(() => ({
        getNetworks: jest.fn()
    })),
    DNSClient: jest.fn().mockImplementation(() => ({
        getPolicies: jest.fn()
    }))
}));

describe('checkDnsLogging', () => {
    const mockComputeClient = new ComputeClient();
    const mockDNSClient = new DNSClient();
    const projectId = 'test-project';

    const mockNetwork = {
        name: 'test-vpc',
        selfLink: 'projects/test-project/global/networks/test-vpc'
    };

    const mockDNSPolicy = {
        enableLogging: true,
        networks: [{
            networkUrl: 'projects/test-project/global/networks/test-vpc'
        }]
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when DNS logging is enabled for VPC networks', async () => {
            mockComputeClient.getNetworks.mockResolvedValue([[mockNetwork]]);
            mockDNSClient.getPolicies.mockResolvedValue([[mockDNSPolicy]]);

            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('test-vpc');
        });

        it('should return NOTAPPLICABLE when no VPC networks exist', async () => {
            mockComputeClient.getNetworks.mockResolvedValue([[]]);

            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No VPC networks found in the project');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when DNS logging is not enabled', async () => {
            mockComputeClient.getNetworks.mockResolvedValue([[mockNetwork]]);
            mockDNSClient.getPolicies.mockResolvedValue([[{
                ...mockDNSPolicy,
                enableLogging: false
            }]]);

            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('Cloud DNS logging is not enabled for this VPC network');
        });

        it('should return FAIL when no DNS policy exists for network', async () => {
            mockComputeClient.getNetworks.mockResolvedValue([[mockNetwork]]);
            mockDNSClient.getPolicies.mockResolvedValue([[]]);

            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });

        it('should handle networks without names', async () => {
            mockComputeClient.getNetworks.mockResolvedValue([[{ selfLink: 'some-link' }]]);
            
            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].resourceName).toBe('Unknown Network');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when getNetworks fails', async () => {
            mockComputeClient.getNetworks.mockRejectedValue(new Error('API Error'));

            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking DNS logging');
        });

        it('should return ERROR when getPolicies fails', async () => {
            mockComputeClient.getNetworks.mockResolvedValue([[mockNetwork]]);
            mockDNSClient.getPolicies.mockRejectedValue(new Error('DNS API Error'));

            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking DNS logging');
        });
    });

    describe('Multiple Resources', () => {
        it('should handle multiple networks with mixed compliance', async () => {
            const networks = [
                mockNetwork,
                { name: 'test-vpc-2', selfLink: 'projects/test-project/global/networks/test-vpc-2' }
            ];
            
            const policies = [
                mockDNSPolicy,
                { enableLogging: false, networks: [{ networkUrl: 'projects/test-project/global/networks/test-vpc-2' }] }
            ];

            mockComputeClient.getNetworks.mockResolvedValue([networks]);
            mockDNSClient.getPolicies.mockResolvedValue([policies]);

            const result = await checkDnsLogging.execute(projectId);
            
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });
});