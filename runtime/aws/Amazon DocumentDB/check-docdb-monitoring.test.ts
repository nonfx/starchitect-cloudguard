// @ts-nocheck
import { DocDBClient, DescribeDBClustersCommand } from '@aws-sdk/client-docdb';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '../../types.js';
import checkDocDBMonitoring from './check-docdb-monitoring';

const mockDocDBClient = mockClient(DocDBClient);

const mockClusterWithMonitoring = {
    DBClusterIdentifier: 'test-cluster-1',
    DBClusterArn: 'arn:aws:docdb:us-east-1:123456789012:cluster:test-cluster-1',
    EnabledCloudwatchLogsExports: ['audit', 'profiler']
};

const mockClusterWithoutMonitoring = {
    DBClusterIdentifier: 'test-cluster-2',
    DBClusterArn: 'arn:aws:docdb:us-east-1:123456789012:cluster:test-cluster-2',
    EnabledCloudwatchLogsExports: []
};

describe('checkDocDBMonitoring', () => {
    beforeEach(() => {
        mockDocDBClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when monitoring is enabled', async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [mockClusterWithMonitoring]
            });

            const result = await checkDocDBMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('test-cluster-1');
            expect(result.checks[0].resourceArn).toBe(mockClusterWithMonitoring.DBClusterArn);
        });

        it('should return NOTAPPLICABLE when no clusters exist', async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: []
            });

            const result = await checkDocDBMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No DocumentDB clusters found in the region');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when monitoring is not enabled', async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [mockClusterWithoutMonitoring]
            });

            const result = await checkDocDBMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('Monitoring is not enabled for this DocumentDB cluster');
        });

        it('should handle clusters with missing identifiers', async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [{ EnabledCloudwatchLogsExports: [] }]
            });

            const result = await checkDocDBMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Cluster found without identifier or ARN');
        });

        it('should handle mixed compliance scenarios', async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [mockClusterWithMonitoring, mockClusterWithoutMonitoring]
            });

            const result = await checkDocDBMonitoring.execute('us-east-1');
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API call fails', async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).rejects(
                new Error('Failed to describe clusters')
            );

            const result = await checkDocDBMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking DocumentDB clusters');
        });

        it('should handle undefined DBClusters response', async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({});

            const result = await checkDocDBMonitoring.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });
});