//@ts-nocheck
import { ApiGatewayV2Client, GetApisCommand, GetRoutesCommand } from "@aws-sdk/client-apigatewayv2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApiGatewayRouteAuthorization from "./check-api-gateway-route-authorization";

const mockApiGatewayClient = mockClient(ApiGatewayV2Client);

const mockApi = {
	ApiId: "test-api-1",
	Name: "TestAPI",
	Arn: "arn:aws:apigateway:us-east-1::/apis/test-api-1"
};

describe("checkApiGatewayRouteAuthorization", () => {
	beforeEach(() => {
		mockApiGatewayClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for routes with valid authorization types", async () => {
			mockApiGatewayClient.on(GetApisCommand).resolves({
				Items: [mockApi]
			});

			mockApiGatewayClient.on(GetRoutesCommand).resolves({
				Items: [
					{ RouteKey: "GET /test1", AuthorizationType: "AWS_IAM" },
					{ RouteKey: "POST /test2", AuthorizationType: "JWT" },
					{ RouteKey: "PUT /test3", AuthorizationType: "CUSTOM" }
				]
			});

			const result = await checkApiGatewayRouteAuthorization.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.PASS);
				expect(check.resourceArn).toBe(`${mockApi.Arn}/routes/undefined`);
			});
		});

		it("should return NOTAPPLICABLE when no routes exist", async () => {
			mockApiGatewayClient.on(GetApisCommand).resolves({
				Items: [mockApi]
			});

			mockApiGatewayClient.on(GetRoutesCommand).resolves({
				Items: []
			});

			const result = await checkApiGatewayRouteAuthorization.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No routes found for this API");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for routes without authorization", async () => {
			mockApiGatewayClient.on(GetApisCommand).resolves({
				Items: [mockApi]
			});

			mockApiGatewayClient.on(GetRoutesCommand).resolves({
				Items: [
					{ RouteKey: "GET /test1", AuthorizationType: "NONE" },
					{ RouteKey: "POST /test2" },
					{ RouteKey: "PUT /test3", AuthorizationType: "INVALID" }
				]
			});

			const result = await checkApiGatewayRouteAuthorization.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.FAIL);
				expect(check.message).toBe("Route does not specify a valid authorization type");
			});
		});

		it("should handle mixed authorization configurations", async () => {
			mockApiGatewayClient.on(GetApisCommand).resolves({
				Items: [mockApi]
			});

			mockApiGatewayClient.on(GetRoutesCommand).resolves({
				Items: [
					{ RouteKey: "GET /test1", AuthorizationType: "AWS_IAM" },
					{ RouteKey: "POST /test2", AuthorizationType: "NONE" }
				]
			});

			const result = await checkApiGatewayRouteAuthorization.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when GetApis fails", async () => {
			mockApiGatewayClient.on(GetApisCommand).rejects(new Error("API Error"));

			const result = await checkApiGatewayRouteAuthorization.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking API Gateway");
		});

		it("should return ERROR when GetRoutes fails", async () => {
			mockApiGatewayClient.on(GetApisCommand).resolves({
				Items: [mockApi]
			});

			mockApiGatewayClient.on(GetRoutesCommand).rejects(new Error("Routes Error"));

			const result = await checkApiGatewayRouteAuthorization.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking routes");
		});

		it("should return NOTAPPLICABLE when no APIs exist", async () => {
			mockApiGatewayClient.on(GetApisCommand).resolves({
				Items: []
			});

			const result = await checkApiGatewayRouteAuthorization.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No API Gateway HTTP/WebSocket APIs found in the region"
			);
		});
	});
});
