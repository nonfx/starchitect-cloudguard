package rules.ensure_encrypted_communications

import data.fugue

__rego__metadoc__ := {
	"id": "11.1",
	"title": "Ensure communications between your applications and clients is encrypted",
	"description": "There is no setting for encryption setup for your clients and applications within SimSpace Weaver service. For this audit you have to confirm that the communication is configured in the app and the client with encryption to protect that traffic.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_11.1"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

# Check AWS ALB listeners
alb_listeners := fugue.resources("aws_lb_listener")

aws_cloudfronts := fugue.resources("aws_cloudfront_distribution")

# Function to check if ALB listener is using HTTPS
is_alb_listener_encrypted(listener) {
	listener.protocol == "HTTPS"
	listener.port == 443
}

is_alb_listener_encrypted(listener) {
	listener.protocol == "TLS"
	listener.port == 443
}

policy[p] {
	listener := alb_listeners[_]
	is_alb_listener_encrypted(listener)
	p = fugue.allow_resource(listener)
}

policy[p] {
	listener := alb_listeners[_]
	not is_alb_listener_encrypted(listener)
	msg := sprintf("ALB Listener '%s' is not serving encrypted traffic", [listener.id])
	p = fugue.deny_resource_with_message(listener, msg)
}

is_cloudfront_encrypted(cloudfront) {
	cloudfront.default_cache_behavior[0].viewer_protocol_policy == "redirect-to-https"
}

is_cloudfront_encrypted(cloudfront) {
	cloudfront.default_cache_behavior[0].viewer_protocol_policy == "https-only"
}

cloudfront_has_valid_certificate(cloudfront) {
	_ = cloudfront.viewer_certificate[0].acm_certificate_arn
}

cloudfront_has_valid_certificate(cloudfront) {
	_ = cloudfront.viewer_certificate[0].iam_certificate_id
}

cloudfront_has_valid_certificate(cloudfront) {
	cloudfront.viewer_certificate[0].cloudfront_default_certificate == true
}

policy[p] {
	cloudfront := aws_cloudfronts[_]
	is_cloudfront_encrypted(cloudfront)
	cloudfront_has_valid_certificate(cloudfront)
	p = fugue.allow_resource(cloudfront)
}

policy[p] {
	cloudfront := aws_cloudfronts[_]
	not is_cloudfront_encrypted(cloudfront)
	msg_cf := sprintf("cloudfront distribution '%s' is not serving encrypted traffic", [cloudfront])
	p = fugue.deny_resource_with_message(cloudfront, msg_cf)
}

policy[p] {
	cloudfront := aws_cloudfronts[_]
	not cloudfront_has_valid_certificate(cloudfront)
	msg_cf := sprintf("cloudfront distribution '%s' is not serving encrypted traffic", [cloudfront])
	p = fugue.deny_resource_with_message(cloudfront, msg_cf)
}
