provider "aws" {
    alias = "pass_aws"
    region = "us-west-2"
}

resource "aws_opensearch_domain" "pass_test_domain" {
    provider = aws.pass_aws
    domain_name = "pass-test-domain"
    
    cluster_config {
        instance_type = "t3.small.search"
        instance_count = 1
    }

    ebs_options {
        ebs_enabled = true
        volume_size = 10
    }

    # Advanced security options enabled with internal user database
    advanced_security_options {
        enabled = true
        internal_user_database_enabled = true
        master_user_options {
            master_user_name = "admin"
            master_user_password = "Test123!"
        }
    }

    encrypt_at_rest {
        enabled = true
    }

    node_to_node_encryption {
        enabled = true
    }

    domain_endpoint_options {
        enforce_https = true
        tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
    }
}
