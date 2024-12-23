import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { IAMClient, GetInstanceProfileCommand } from '@aws-sdk/client-iam';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '@codegen/utils/stringUtils';
import checkEc2SystemsManagerCompliance from './aws_ec2_systems_manager';

const mockEC2Client = mockClient(EC2Client);
const mockIAMClient = mockClient(IAMClient);

const mockInstance = {
    InstanceId: 'i-1234567890abcdef0',
    IamInstanceProfile: {
        Arn: 'arn:aws:iam::123456789012:instance-profile/test-profile'
    }
};

describe('checkEc2SystemsManagerCompliance', () => {
    beforeEach(() => {
        mockEC2Client.reset();
        mockIAMClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when instance has SSM policy attached', async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [mockInstance]
                }]
            });

            mockIAMClient.on(GetInstanceProfileCommand).resolves({
                InstanceProfile: {
                    Roles: [{
                        AssumeRolePolicyDocument: 'AmazonSSMManagedInstanceCore'
                    }]
                }
            });

            const result = await checkEc2SystemsManagerCompliance();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockInstance.InstanceId);
        });

        it('should return NOTAPPLICABLE when no instances exist', async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: []
            });

            const result = await checkEc2SystemsManagerCompliance();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No EC2 instances found in the region');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when instance has no IAM profile', async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [{
                        InstanceId: 'i-1234567890abcdef0'
                    }]
                }]
            });

            const result = await checkEc2SystemsManagerCompliance();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('EC2 instance does not have an IAM instance profile attached');
        });

        it('should return FAIL when instance profile lacks SSM policy', async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [mockInstance]
                }]
            });

            mockIAMClient.on(GetInstanceProfileCommand).resolves({
                InstanceProfile: {
                    Roles: [{
                        AssumeRolePolicyDocument: 'SomeOtherPolicy'
                    }]
                }
            });

            const result = await checkEc2SystemsManagerCompliance();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('Instance profile does not have AmazonSSMManagedInstanceCore policy attached');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when EC2 API call fails', async () => {
            mockEC2Client.on(DescribeInstancesCommand).rejects(new Error('EC2 API Error'));

            const result = await checkEc2SystemsManagerCompliance();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking EC2 instances');
        });

        it('should return ERROR when IAM API call fails', async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [mockInstance]
                }]
            });

            mockIAMClient.on(GetInstanceProfileCommand).rejects(new Error('IAM API Error'));

            const result = await checkEc2SystemsManagerCompliance();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking instance profile');
        });

        it('should handle multiple instances with mixed results', async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [
                        mockInstance,
                        {
                            InstanceId: 'i-0987654321fedcba0',
                            IamInstanceProfile: {
                                Arn: 'arn:aws:iam::123456789012:instance-profile/test-profile-2'
                            }
                        }
                    ]
                }]
            });

            mockIAMClient
                .on(GetInstanceProfileCommand)
                .resolvesOnce({
                    InstanceProfile: {
                        Roles: [{
                            AssumeRolePolicyDocument: 'AmazonSSMManagedInstanceCore'
                        }]
                    }
                })
                .resolvesOnce({
                    InstanceProfile: {
                        Roles: [{
                            AssumeRolePolicyDocument: 'SomeOtherPolicy'
                        }]
                    }
                });

            const result = await checkEc2SystemsManagerCompliance();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });
});