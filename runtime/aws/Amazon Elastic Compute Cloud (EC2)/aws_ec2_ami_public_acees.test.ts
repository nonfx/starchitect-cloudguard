import { EC2Client, DescribeImagesCommand } from '@aws-sdk/client-ec2';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '@codegen/utils/stringUtils';
import checkPublicAMIs from './aws_ec2_ami_public_acees';

const mockEC2Client = mockClient(EC2Client);

const mockPrivateAMI = {
    ImageId: 'ami-12345678',
    Public: false,
    Name: 'private-ami'
};

const mockPublicAMI = {
    ImageId: 'ami-87654321',
    Public: true,
    Name: 'public-ami'
};

describe('checkPublicAMIs', () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS for private AMIs', async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [mockPrivateAMI]
            });

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('ami-12345678');
            expect(result.checks[0].resourceArn).toBe('arn:aws:ec2:us-east-1::image/ami-12345678');
        });

        it('should return NOTAPPLICABLE when no AMIs exist', async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: []
            });

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No AMIs found in the account');
        });

        it('should handle multiple private AMIs', async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [
                    mockPrivateAMI,
                    { ...mockPrivateAMI, ImageId: 'ami-98765432' }
                ]
            });

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL for public AMIs', async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [mockPublicAMI]
            });

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('AMI is publicly accessible');
        });

        it('should handle mixed public and private AMIs', async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [mockPrivateAMI, mockPublicAMI]
            });

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it('should handle AMIs without ImageId', async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [{ Public: false }]
            });

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('AMI found without Image ID');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API call fails', async () => {
            mockEC2Client.on(DescribeImagesCommand).rejects(new Error('API Error'));

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Error checking AMIs: API Error');
        });

        it('should handle undefined Images response', async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({});

            const result = await checkPublicAMIs('us-east-1');
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No AMIs found in the account');
        });
    });
});
