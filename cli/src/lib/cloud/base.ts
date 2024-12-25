import type { RuntimeTest } from "../../types";

export abstract class CloudProvider {
	abstract detectCredentials(): Promise<boolean>;
	abstract validateCredentials(): Promise<boolean>;
	abstract getTests(): Promise<RuntimeTest[]>;
	abstract getTestArguments(): Promise<unknown[]>;
	abstract getRegions(): Promise<string[]>;
}
