// @ts-nocheck
import { APIGatewayClient, GetStagesCommand } from '@aws-sdk/client-api-gateway';
import { WAFRegionalClient, ListResourcesForWebACLCommand } from '@aws-sdk/client-waf-regional';
import { mockClient } from 'aws-sdk-client-mock';
import { ComplianceStatus } from '../../types.js';
import checkApiGatewayWaf from './check-api-gateway-waf';

const mockApiGatewayClient = mockClient(APIGatewayClient);
const mockWafRegionalClient = mockClient(WAFRegionalClient);

describe('checkApiGatewayWaf', () => {
    beforeEach(() => {
        mockApiGatewayClient.reset();
        mockWafRegionalClient.reset();
    });

    describe('Compliant Resources', () => {
        it('should return PASS when API Gateway stage has WAF Web ACL', async () => {
            mockApiGatewayClient.on(GetStagesCommand).resolves({
                item: [{
                    stageName: 'prod',
                    webAclArn: 'arn:aws:wafregional:us-east-1:123456789012:webacl/test-acl'
                }]
            });

            mockWafRegionalClient.on(ListResourcesForWebACLCommand).resolves({
                ResourceArns: ['arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod']
            });

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe('prod');
        });

        it('should return NOTAPPLICABLE when no API Gateway stages exist', async () => {
            mockApiGatewayClient.on(GetStagesCommand).resolves({
                item: []
            });

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe('No API Gateway stages found in the region');
        });

        it('should handle multiple compliant stages', async () => {
            mockApiGatewayClient.on(GetStagesCommand).resolves({
                item: [
                    { stageName: 'prod', webAclArn: 'arn:aws:wafregional::/webacl/prod-acl' },
                    { stageName: 'dev', webAclArn: 'arn:aws:wafregional::/webacl/dev-acl' }
                ]
            });

            mockWafRegionalClient.on(ListResourcesForWebACLCommand).resolves({
                ResourceArns: ['arn:aws:apigateway::/stages/test']
            });

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe('Non-Compliant Resources', () => {
        it('should return FAIL when API Gateway stage has no WAF Web ACL', async () => {
            mockApiGatewayClient.on(GetStagesCommand).resolves({
                item: [{
                    stageName: 'prod'
                }]
            });

            mockWafRegionalClient.on(ListResourcesForWebACLCommand).resolves({
                ResourceArns: []
            });

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe('API Gateway stage is not associated with a WAF Web ACL');
        });

        it('should handle mixed compliance results', async () => {
            mockApiGatewayClient.on(GetStagesCommand).resolves({
                item: [
                    { stageName: 'prod', webAclArn: 'arn:aws:wafregional::/webacl/prod-acl' },
                    { stageName: 'dev' }
                ]
            });

            mockWafRegionalClient
                .on(ListResourcesForWebACLCommand)
                .resolvesOnce({ ResourceArns: ['arn:aws:apigateway::/stages/prod'] })
                .resolvesOnce({ ResourceArns: [] });

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe('Error Handling', () => {
        it('should return ERROR when API Gateway call fails', async () => {
            mockApiGatewayClient.on(GetStagesCommand).rejects(new Error('API Gateway Error'));

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking API Gateway stages');
        });

        it('should return ERROR when WAF call fails', async () => {
            mockApiGatewayClient.on(GetStagesCommand).resolves({
                item: [{ stageName: 'prod', webAclArn: 'arn:aws:wafregional::/webacl/test' }]
            });

            mockWafRegionalClient.on(ListResourcesForWebACLCommand).rejects(new Error('WAF Error'));

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain('Error checking WAF association');
        });

        it('should handle stages without names', async () => {
            mockApiGatewayClient.on(GetStagesCommand).resolves({
                item: [{}]
            });

            const result = await checkApiGatewayWaf.execute('us-east-1');
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe('Stage found without name');
        });
    });
});