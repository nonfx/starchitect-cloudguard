import pino from "pino";

// @todo - remove logger and rely on base class from oclif
export const logger = pino({
	level: process.env.LOG_LEVEL || "info",
	transport: {
		target: "pino-pretty",
		options: {
			colorize: true
		}
	}
});
