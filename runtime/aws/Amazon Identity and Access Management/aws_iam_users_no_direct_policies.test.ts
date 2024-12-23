import { IAMClient, ListUsersCommand, ListAttachedUserPoliciesCommand, ListUserPoliciesCommand } from '@aws-sdk/client-iam';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '@codegen/utils/stringUtils';
import checkIamUserPolicies from './aws_iam_users_no_direct_policies';

const mockIAMClient = mockClient(IAMClient);

const mockUsers = [
    {
        UserName: 'user1',
        Arn: 'arn:aws:iam::123456789012:user/user1',
        CreateDate: new Date()
    },
    {
        UserName: 'user2',
        Arn: 'arn:aws:iam::123456789012:user/user2',
        CreateDate: new Date()
    }
];

describe('checkIamUserPolicies', () => {
    beforeEach(() => {
        mockIAMClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when users have no policies attached', async () => {
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: mockUsers })
                .on(ListAttachedUserPoliciesCommand).resolves({ AttachedPolicies: [] })
                .on(ListUserPoliciesCommand).resolves({ PolicyNames: [] });

            const result = await checkIamUserPolicies();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });

        it('should return NOTAPPLICABLE when no users exist', async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

            const result = await checkIamUserPolicies();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No IAM users found');
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when users have attached policies', async () => {
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[0]] })
                .on(ListAttachedUserPoliciesCommand).resolves({
                    AttachedPolicies: [{
                        PolicyName: 'AdminAccess',
                        PolicyArn: 'arn:aws:iam::aws:policy/AdminAccess'
                    }]
                })
                .on(ListUserPoliciesCommand).resolves({ PolicyNames: [] });

            const result = await checkIamUserPolicies();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('attached');
        });

        it('should return FAIL when users have inline policies', async () => {
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[0]] })
                .on(ListAttachedUserPoliciesCommand).resolves({ AttachedPolicies: [] })
                .on(ListUserPoliciesCommand).resolves({ PolicyNames: ['InlinePolicy1'] });

            const result = await checkIamUserPolicies();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('inline');
        });

        it('should return FAIL when users have both attached and inline policies', async () => {
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[0]] })
                .on(ListAttachedUserPoliciesCommand).resolves({
                    AttachedPolicies: [{
                        PolicyName: 'AdminAccess',
                        PolicyArn: 'arn:aws:iam::aws:policy/AdminAccess'
                    }]
                })
                .on(ListUserPoliciesCommand).resolves({ PolicyNames: ['InlinePolicy1'] });

            const result = await checkIamUserPolicies();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain('attached and inline');
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when ListUsers fails', async () => {
            mockIAMClient.on(ListUsersCommand).rejects(new Error('Failed to list users'));

            const result = await checkIamUserPolicies();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Failed to list users');
        });

        it('should return ERROR for specific users when policy checks fail', async () => {
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[0]] })
                .on(ListAttachedUserPoliciesCommand).rejects(new Error('Access denied'));

            const result = await checkIamUserPolicies();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking user policies');
        });

        it('should handle users without UserName or ARN', async () => {
            mockIAMClient.on(ListUsersCommand).resolves({
                Users: [{ CreateDate: new Date() }]
            });

            const result = await checkIamUserPolicies();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('User found without name or ARN');
        });
    });
});