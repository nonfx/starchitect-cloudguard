package main

# Deny AWS provider configurations that don't specify a region
deny[msg] {
    resource := input.provider[_]
    resource.aws
    not resource.aws.region
    msg = "AWS provider must specify a region"
}

# Ensure all S3 buckets have versioning enabled
deny[msg] {
    resource := input.resource.aws_s3_bucket[_]
    not resource.versioning
    msg = sprintf("S3 bucket '%v' must have versioning enabled", [resource.bucket])
}

# Ensure all EBS volumes are encrypted
deny[msg] {
    resource := input.resource.aws_ebs_volume[_]
    not resource.encrypted
    msg = "EBS volumes must be encrypted"
}

# Ensure all RDS instances are encrypted
deny[msg] {
    resource := input.resource.aws_db_instance[_]
    not resource.storage_encrypted
    msg = sprintf("RDS instance '%v' must have storage encryption enabled", [resource.identifier])
}
