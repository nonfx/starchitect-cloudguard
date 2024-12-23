export const DEFAULT_REGION = "us-east-1";

export interface AWSClientConfig {
	region?: string;
	credentials?: {
		accessKeyId: string;
		secretAccessKey: string;
	};
}
export function createBaseConfig(config?: AWSClientConfig) {
	return {
		region: config?.region ?? DEFAULT_REGION,
		credentials: config?.credentials
	};
}
export function isValidRegion(region: string): boolean {
	const regionRegex = /^[a-z]{2}-[a-z]+-\d{1}$/;
	return regionRegex.test(region);
}
