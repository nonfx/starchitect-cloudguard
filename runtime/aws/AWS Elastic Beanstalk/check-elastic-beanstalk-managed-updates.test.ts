//@ts-nocheck
import { ElasticBeanstalkClient, DescribeEnvironmentsCommand, DescribeConfigurationSettingsCommand } from '@aws-sdk/client-elastic-beanstalk';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '../../types.js';
import checkElasticBeanstalkManagedUpdates from './check-elastic-beanstalk-managed-updates';

const mockElasticBeanstalkClient = mockClient(ElasticBeanstalkClient);

const mockEnvironment = {
    EnvironmentName: 'test-env',
    EnvironmentId: 'e-123456789',
    ApplicationName: 'test-app',
    EnvironmentArn: 'arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/test-app/test-env'
};

describe('checkElasticBeanstalkManagedUpdates', () => {
    beforeEach(() => {
        mockElasticBeanstalkClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when managed updates are enabled', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .resolves({
                    ConfigurationSettings: [{
                        OptionSettings: [{
                            OptionName: 'ManagedActionsEnabled',
                            Value: 'true'
                        }]
                    }]
                });

            const result = await checkElasticBeanstalkManagedUpdates.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('test-env');
        });

        it('should return NOTAPPLICABLE when no environments exist', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [] });

            const result = await checkElasticBeanstalkManagedUpdates.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No Elastic Beanstalk environments found in the region');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when managed updates are disabled', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .resolves({
                    ConfigurationSettings: [{
                        OptionSettings: [{
                            OptionName: 'ManagedActionsEnabled',
                            Value: 'false'
                        }]
                    }]
                });

            const result = await checkElasticBeanstalkManagedUpdates.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('Managed Platform updates is not configured');
        });

        it('should return FAIL when managed updates setting is missing', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .resolves({
                    ConfigurationSettings: [{
                        OptionSettings: []
                    }]
                });

            const result = await checkElasticBeanstalkManagedUpdates.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when DescribeEnvironments fails', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .rejects(new Error('API Error'));

            const result = await checkElasticBeanstalkManagedUpdates.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking Elastic Beanstalk environments');
        });

        it('should return ERROR when DescribeConfigurationSettings fails', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .rejects(new Error('Configuration Error'));

            const result = await checkElasticBeanstalkManagedUpdates.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking configuration settings');
        });

        it('should handle environments without name or ID', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ 
                    Environments: [{ ApplicationName: 'test-app' }] 
                });

            const result = await checkElasticBeanstalkManagedUpdates.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Environment found without name or ID');
        });
    });
});