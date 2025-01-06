// @ts-nocheck
import { ElasticBeanstalkClient, DescribeEnvironmentsCommand, DescribeConfigurationSettingsCommand } from '@aws-sdk/client-elastic-beanstalk';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '../../types.js';
import checkBeanstalkPersistentLogs from './check-beanstalk-persistent-logs';

const mockElasticBeanstalkClient = mockClient(ElasticBeanstalkClient);

const mockEnvironment = {
    EnvironmentName: 'test-env',
    EnvironmentId: 'e-123456789',
    ApplicationName: 'test-app',
    EnvironmentArn: 'arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/test-app/test-env'
};

describe('checkBeanstalkPersistentLogs', () => {
    beforeEach(() => {
        mockElasticBeanstalkClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when logs are properly configured', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .resolves({
                    ConfigurationSettings: [{
                        OptionSettings: [
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'StreamLogs',
                                Value: 'true'
                            },
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'RetentionInDays',
                                Value: '7'
                            },
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'DeleteOnTerminate',
                                Value: 'false'
                            }
                        ]
                    }]
                });

            const result = await checkBeanstalkPersistentLogs.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('test-env');
        });

        it('should return NOTAPPLICABLE when no environments exist', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [] });

            const result = await checkBeanstalkPersistentLogs.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No Elastic Beanstalk environments found in the region');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when log streaming is disabled', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .resolves({
                    ConfigurationSettings: [{
                        OptionSettings: [
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'StreamLogs',
                                Value: 'false'
                            },
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'RetentionInDays',
                                Value: '7'
                            },
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'DeleteOnTerminate',
                                Value: 'false'
                            }
                        ]
                    }]
                });

            const result = await checkBeanstalkPersistentLogs.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('Log streaming is not enabled');
        });

        it('should return FAIL when retention is not configured', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .resolves({
                    ConfigurationSettings: [{
                        OptionSettings: [
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'StreamLogs',
                                Value: 'true'
                            },
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'RetentionInDays',
                                Value: '0'
                            },
                            {
                                Namespace: 'aws:elasticbeanstalk:cloudwatch:logs',
                                OptionName: 'DeleteOnTerminate',
                                Value: 'false'
                            }
                        ]
                    }]
                });

            const result = await checkBeanstalkPersistentLogs.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('Log retention is not configured');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API call fails', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .rejects(new Error('API Error'));

            const result = await checkBeanstalkPersistentLogs.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking Elastic Beanstalk environments');
        });

        it('should return ERROR when environment configuration check fails', async () => {
            mockElasticBeanstalkClient
                .on(DescribeEnvironmentsCommand)
                .resolves({ Environments: [mockEnvironment] });
            
            mockElasticBeanstalkClient
                .on(DescribeConfigurationSettingsCommand)
                .rejects(new Error('Configuration Error'));

            const result = await checkBeanstalkPersistentLogs.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking environment configuration');
        });
    });
});