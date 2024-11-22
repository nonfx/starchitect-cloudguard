package rules.aws_elastic_beanstalk_access_logs_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "6.3",
	"title": "Ensure access logs are enabled",
	"description": "When you enable load balancing, your AWS Elastic Beanstalk environment is equipped with an Elastic Load Balancing load balancer to distribute traffic among the instances in your environment",
	"custom": {"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.3"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

elastic_beanstalk_environments = fugue.resources("aws_elastic_beanstalk_environment")

# Helper to check if Classic Load Balancer is used
uses_elb(env) {
	setting := env.setting[_]
	setting.namespace == "aws:elb:loadbalancer"
}

# Helper to check if Application Load Balancer is used
uses_elbv2(env) {
	setting := env.setting[_]
	setting.namespace == "aws:elbv2:loadbalancer"
}

# Helper to check access log settings for Classic Load Balancers
access_logs_enabled_elb(env) {
	setting := env.setting[_]
	setting.namespace == "aws:elb:loadbalancer"
	setting.name == "AccessLogsS3Enabled"
	setting.value == "true"
}

# Helper to check access log settings for Application Load Balancers
access_logs_enabled_elbv2(env) {
	setting := env.setting[_]
	setting.namespace == "aws:elbv2:loadbalancer"
	setting.name == "AccessLogsS3Enabled"
	setting.value == "true"
}

policy[p] {
	env := elastic_beanstalk_environments[_]
	uses_elb(env)
	access_logs_enabled_elb(env)
	p := fugue.allow_resource(env)
}

policy[p] {
	env := elastic_beanstalk_environments[_]
	uses_elbv2(env)
	access_logs_enabled_elbv2(env)
	p := fugue.allow_resource(env)
}

policy[p] {
	env := elastic_beanstalk_environments[_]
	uses_elb(env)
	not access_logs_enabled_elb(env)
	p := fugue.deny_resource_with_message(env, "Access logs are not enabled for this Elastic Beanstalk environment with classic load balancing")
}

policy[p] {
	env := elastic_beanstalk_environments[_]
	uses_elbv2(env)
	not access_logs_enabled_elbv2(env)
	p := fugue.deny_resource_with_message(env, "Access logs are not enabled for this Elastic Beanstalk environment with application load balancing")
}

policy[p] {
	env := elastic_beanstalk_environments[_]
	not uses_elb(env)
	not uses_elbv2(env)
	p := fugue.allow_resource(env)
}
