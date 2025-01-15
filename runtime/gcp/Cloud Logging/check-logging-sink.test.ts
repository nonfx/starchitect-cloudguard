// @ts-nocheck
import { LoggingClient } from '@google-cloud/logging';
import { ComplianceStatus } from '../../types.js';
import checkLoggingSink from './check-logging-sink';

jest.mock('@google-cloud/logging');

describe('checkLoggingSink', () => {
    const mockGetSinks = jest.fn();
    
    beforeEach(() => {
        jest.resetAllMocks();
        (LoggingClient as jest.Mock).mockImplementation(() => ({
            getSinks: mockGetSinks
        }));
    });

    describe('Compliant Resources', () => {
        it('should return PASS when sinks are properly configured', async () => {
            const mockSinks = [
                {
                    name: 'proper-sink-1',
                    destination: 'storage.googleapis.com/my-bucket',
                    filter: undefined
                },
                {
                    name: 'proper-sink-2',
                    destination: 'bigquery.googleapis.com/projects/my-project/datasets/my_dataset',
                    filter: undefined
                }
            ];

            mockGetSinks.mockResolvedValue([mockSinks]);

            const result = await checkLoggingSink.execute();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('proper-sink-1');
            expect(result.checks[1].resourceName).toBe('proper-sink-2');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when no sinks exist', async () => {
            mockGetSinks.mockResolvedValue([[]]);

            const result = await checkLoggingSink.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('No logging sinks found');
        });

        it('should return FAIL when sinks have filters', async () => {
            const mockSinks = [
                {
                    name: 'filtered-sink',
                    destination: 'storage.googleapis.com/my-bucket',
                    filter: 'severity >= WARNING'
                }
            ];

            mockGetSinks.mockResolvedValue([mockSinks]);

            const result = await checkLoggingSink.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('has a filter configured');
        });

        it('should return FAIL when sinks have no destination', async () => {
            const mockSinks = [
                {
                    name: 'invalid-sink',
                    destination: undefined,
                    filter: undefined
                }
            ];

            mockGetSinks.mockResolvedValue([mockSinks]);

            const result = await checkLoggingSink.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('does not have a valid destination');
        });

        it('should handle mixed compliance results', async () => {
            const mockSinks = [
                {
                    name: 'proper-sink',
                    destination: 'storage.googleapis.com/my-bucket',
                    filter: undefined
                },
                {
                    name: 'filtered-sink',
                    destination: 'storage.googleapis.com/my-bucket',
                    filter: 'severity >= WARNING'
                }
            ];

            mockGetSinks.mockResolvedValue([mockSinks]);

            const result = await checkLoggingSink.execute();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API call fails', async () => {
            mockGetSinks.mockRejectedValue(new Error('API Error'));

            const result = await checkLoggingSink.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking logging sinks');
        });

        it('should handle undefined sink name', async () => {
            const mockSinks = [
                {
                    destination: 'storage.googleapis.com/my-bucket',
                    filter: undefined
                }
            ];

            mockGetSinks.mockResolvedValue([mockSinks]);

            const result = await checkLoggingSink.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].resourceName).toBe('Unknown Sink');
        });
    });
});