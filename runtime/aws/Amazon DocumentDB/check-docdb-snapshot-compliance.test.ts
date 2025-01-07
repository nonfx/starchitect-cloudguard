//@ts-nocheck
import { DocDBClient, DescribeDBClusterSnapshotsCommand } from '@aws-sdk/client-docdb';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '../../types.js';
import checkDocDBSnapshotCompliance from './check-docdb-snapshot-compliance';

const mockDocDBClient = mockClient(DocDBClient);

const mockPublicSnapshot = {
    DBClusterSnapshotIdentifier: 'public-snapshot',
    DBClusterSnapshotArn: 'arn:aws:rds:us-east-1:123456789012:cluster-snapshot:public-snapshot',
    AttributeValues: ['all']
};

const mockPrivateSnapshot = {
    DBClusterSnapshotIdentifier: 'private-snapshot',
    DBClusterSnapshotArn: 'arn:aws:rds:us-east-1:123456789012:cluster-snapshot:private-snapshot',
    AttributeValues: []
};

describe('checkDocDBSnapshotCompliance', () => {
    beforeEach(() => {
        mockDocDBClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS for private snapshots', async () => {
            mockDocDBClient.on(DescribeDBClusterSnapshotsCommand).resolves({
                DBClusterSnapshots: [mockPrivateSnapshot]
            });

            const result = await checkDocDBSnapshotCompliance.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('private-snapshot');
            expect(result.checks[0].resourceArn).toBe(mockPrivateSnapshot.DBClusterSnapshotArn);
        });

        it('should return NOTAPPLICABLE when no snapshots exist', async () => {
            mockDocDBClient.on(DescribeDBClusterSnapshotsCommand).resolves({
                DBClusterSnapshots: []
            });

            const result = await checkDocDBSnapshotCompliance.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No manual DocumentDB cluster snapshots found');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL for public snapshots', async () => {
            mockDocDBClient.on(DescribeDBClusterSnapshotsCommand).resolves({
                DBClusterSnapshots: [mockPublicSnapshot]
            });

            const result = await checkDocDBSnapshotCompliance.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('DocumentDB cluster snapshot is publicly accessible');
        });

        it('should handle mixed public and private snapshots', async () => {
            mockDocDBClient.on(DescribeDBClusterSnapshotsCommand).resolves({
                DBClusterSnapshots: [mockPublicSnapshot, mockPrivateSnapshot]
            });

            const result = await checkDocDBSnapshotCompliance.execute('us-east-1');
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });

        it('should handle snapshots with missing identifiers', async () => {
            mockDocDBClient.on(DescribeDBClusterSnapshotsCommand).resolves({
                DBClusterSnapshots: [{ AttributeValues: ['all'] }]
            });

            const result = await checkDocDBSnapshotCompliance.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Snapshot found without identifier or ARN');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API call fails', async () => {
            mockDocDBClient.on(DescribeDBClusterSnapshotsCommand).rejects(
                new Error('API Error')
            );

            const result = await checkDocDBSnapshotCompliance.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking DocumentDB snapshots: API Error');
        });

        it('should handle undefined response', async () => {
            mockDocDBClient.on(DescribeDBClusterSnapshotsCommand).resolves({});

            const result = await checkDocDBSnapshotCompliance.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });
});