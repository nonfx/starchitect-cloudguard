// @ts-nocheck
import { ComputeClient } from '@google-cloud/compute';
import { ComplianceStatus } from '../../types.js';
import checkLoadBalancerLogging from './check-load-balancer-logging';

jest.mock('@google-cloud/compute');

describe('checkLoadBalancerLogging', () => {
    const mockListBackendServices = jest.fn();
    
    beforeEach(() => {
        jest.resetAllMocks();
        (ComputeClient as jest.Mock).mockImplementation(() => ({
            listBackendServices: mockListBackendServices
        }));
    });

    describe('Compliant Resources', () => {
        it('should return PASS when logging is properly configured', async () => {
            const mockServices = [[{
                name: 'backend-service-1',
                selfLink: 'projects/test-project/global/backendServices/backend-service-1',
                logConfig: {
                    enable: true,
                    sampleRate: 1.0
                }
            }]];

            mockListBackendServices.mockResolvedValue(mockServices);

            const result = await checkLoadBalancerLogging.execute('test-project');
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('backend-service-1');
        });

        it('should return NOTAPPLICABLE when no backend services exist', async () => {
            mockListBackendServices.mockResolvedValue([[]]);

            const result = await checkLoadBalancerLogging.execute('test-project');
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No HTTP(S) Load Balancer backend services found');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when logging is disabled', async () => {
            const mockServices = [[{
                name: 'backend-service-1',
                selfLink: 'projects/test-project/global/backendServices/backend-service-1',
                logConfig: {
                    enable: false,
                    sampleRate: 1.0
                }
            }]];

            mockListBackendServices.mockResolvedValue(mockServices);

            const result = await checkLoadBalancerLogging.execute('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('Backend service logging is not properly configured');
        });

        it('should return FAIL when sample rate is 0', async () => {
            const mockServices = [[{
                name: 'backend-service-1',
                selfLink: 'projects/test-project/global/backendServices/backend-service-1',
                logConfig: {
                    enable: true,
                    sampleRate: 0
                }
            }]];

            mockListBackendServices.mockResolvedValue(mockServices);

            const result = await checkLoadBalancerLogging.execute('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });

        it('should handle multiple backend services with mixed compliance', async () => {
            const mockServices = [[
                {
                    name: 'compliant-service',
                    selfLink: 'projects/test-project/global/backendServices/compliant-service',
                    logConfig: {
                        enable: true,
                        sampleRate: 1.0
                    }
                },
                {
                    name: 'non-compliant-service',
                    selfLink: 'projects/test-project/global/backendServices/non-compliant-service',
                    logConfig: {
                        enable: false,
                        sampleRate: 0
                    }
                }
            ]];

            mockListBackendServices.mockResolvedValue(mockServices);

            const result = await checkLoadBalancerLogging.execute('test-project');
            
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API call fails', async () => {
            mockListBackendServices.mockRejectedValue(new Error('API Error'));

            const result = await checkLoadBalancerLogging.execute('test-project');
            
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking backend services');
        });

        it('should handle backend services without names', async () => {
            const mockServices = [[{
                selfLink: 'projects/test-project/global/backendServices/unnamed-service',
                logConfig: {
                    enable: true,
                    sampleRate: 1.0
                }
            }]];

            mockListBackendServices.mockResolvedValue(mockServices);

            const result = await checkLoadBalancerLogging.execute('test-project');
            
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Backend service found without name');
        });
    });
});