package rules.aws_elastic_beanstalk_https_enabled

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "6.4",
	"title": "Ensure that HTTPS is enabled on load balancer",
	"description": "The simplest way to use HTTPS with an Elastic Beanstalk environment is to assign a server certificate to your environment's load balancer. When you configure your load balancer to terminate HTTPS, the connection between the client and the load balancer is secure.",
	"custom": {"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.4"]}},
}

resource_type := "MULTIPLE"

elastic_beanstalk_environments = fugue.resources("aws_elastic_beanstalk_environment")

https_enabled(env) {
	setting := env.setting[_]
	setting.namespace == "aws:elb:listener:443"
	setting.name == "ListenerProtocol"
	setting.value == "HTTPS"
}

policy[p] {
	env := elastic_beanstalk_environments[_]
	https_enabled(env)
	p := fugue.allow_resource(env)
}

policy[p] {
	env := elastic_beanstalk_environments[_]
	not https_enabled(env)
	p := fugue.deny_resource_with_message(env, "HTTPS is not enabled on the load balancer for this Elastic Beanstalk environment")
}
