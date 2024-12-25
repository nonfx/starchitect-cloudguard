import amazon_elastic_compute_cloud_ec2_aws_autoscaling_multiple_instance_types from "./Amazon Elastic Compute Cloud (EC2)/aws_autoscaling_multiple_instance_types";
import amazon_simple_storage_service_amazon_s3_check_s3_data_discovery_compliance from "./Amazon Simple Storage Service (Amazon S3)/check-s3-data-discovery-compliance";
import amazon_simple_storage_service_amazon_s3_check_s3_object_level_logging from "./Amazon Simple Storage Service (Amazon S3)/check-s3-object-level-logging";
import amazon_simple_storage_service_amazon_s3_check_s3_block_public_access from "./Amazon Simple Storage Service (Amazon S3)/check-s3-block-public-access";
import amazon_simple_storage_service_amazon_s3_check_s3_object_read_logging from "./Amazon Simple Storage Service (Amazon S3)/check-s3-object-read-logging";
import amazon_simple_storage_service_amazon_s3_check_s3_deny_http_access from "./Amazon Simple Storage Service (Amazon S3)/check-s3-deny-http-access";
import amazon_simple_storage_service_amazon_s3_aws_s3_http_access_deny from "./Amazon Simple Storage Service (Amazon S3)/aws_s3_http_access_deny";
import amazon_simple_storage_service_amazon_s3_check_s3_ssl_required_copy from "./Amazon Simple Storage Service (Amazon S3)/check-s3-ssl-required copy";
import amazon_simple_storage_service_amazon_s3_check_s3_bucket_external_access from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-external-access";
import amazon_simple_storage_service_amazon_s3_check_s3_mfa_delete from "./Amazon Simple Storage Service (Amazon S3)/check-s3-mfa-delete";
import amazon_simple_storage_service_amazon_s3_check_s3_bucket_acl_compliance from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-acl-compliance";
import amazon_simple_storage_service_amazon_s3_check_s3_bucket_logging from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-logging";
import amazon_simple_storage_service_amazon_s3_aws_s3_mfa_delete_enabled from "./Amazon Simple Storage Service (Amazon S3)/aws_s3_mfa_delete_enabled";
import amazon_simple_storage_service_amazon_s3_check_s3_ssl_required from "./Amazon Simple Storage Service (Amazon S3)/check-s3-ssl-required";
import amazon_simple_storage_service_amazon_s3_check_s3_access_point_block_public_access from "./Amazon Simple Storage Service (Amazon S3)/check-s3-access-point-block-public-access";
import amazon_simple_storage_service_amazon_s3_check_s3_bucket_lifecycle_configuration from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-lifecycle-configuration";
import amazon_virtual_private_cloud_check_default_security_group_compliance from "./Amazon Virtual Private Cloud/check-default-security-group-compliance";
import amazon_virtual_private_cloud_check_vpc_peering_routing_compliance from "./Amazon Virtual Private Cloud/check-vpc-peering-routing-compliance";
import amazon_virtual_private_cloud_check_nacl_port22_compliance from "./Amazon Virtual Private Cloud/check-nacl-port22-compliance";
import amazon_virtual_private_cloud_check_security_group_admin_ports from "./Amazon Virtual Private Cloud/check-security-group-admin-ports";
import amazon_virtual_private_cloud_check_vpc_flow_logs from "./Amazon Virtual Private Cloud/check-vpc-flow-logs";
import aws_cloudtrail_check_cloudtrail_log_validation from "./AWS CloudTrail/check-cloudtrail-log-validation";
import aws_cloudtrail_check_cloudtrail_enabled from "./AWS CloudTrail/check-cloudtrail-enabled";
import aws_cloudtrail_check_cloudtrail_s3_access_logging from "./AWS CloudTrail/check-cloudtrail-s3-access-logging";
import aws_cloudtrail_check_cloudtrail_kms_encryption from "./AWS CloudTrail/check-cloudtrail-kms-encryption";
import aws_cloudtrail_check_cloudtrail_tagged from "./AWS CloudTrail/check-cloudtrail-tagged";
import aws_cloudtrail_check_cloudtrail_multiregion from "./AWS CloudTrail/check-cloudtrail-multiregion";
import aws_cloudtrail_check_cloudtrail_encryption from "./AWS CloudTrail/check-cloudtrail-encryption";

const allTests = [
	amazon_elastic_compute_cloud_ec2_aws_autoscaling_multiple_instance_types,
	amazon_simple_storage_service_amazon_s3_check_s3_data_discovery_compliance,
	amazon_simple_storage_service_amazon_s3_check_s3_object_level_logging,
	amazon_simple_storage_service_amazon_s3_check_s3_block_public_access,
	amazon_simple_storage_service_amazon_s3_check_s3_object_read_logging,
	amazon_simple_storage_service_amazon_s3_check_s3_deny_http_access,
	amazon_simple_storage_service_amazon_s3_aws_s3_http_access_deny,
	amazon_simple_storage_service_amazon_s3_check_s3_ssl_required_copy,
	amazon_simple_storage_service_amazon_s3_check_s3_bucket_external_access,
	amazon_simple_storage_service_amazon_s3_check_s3_mfa_delete,
	amazon_simple_storage_service_amazon_s3_check_s3_bucket_acl_compliance,
	amazon_simple_storage_service_amazon_s3_check_s3_bucket_logging,
	amazon_simple_storage_service_amazon_s3_aws_s3_mfa_delete_enabled,
	amazon_simple_storage_service_amazon_s3_check_s3_ssl_required,
	amazon_simple_storage_service_amazon_s3_check_s3_access_point_block_public_access,
	amazon_simple_storage_service_amazon_s3_check_s3_bucket_lifecycle_configuration,
	amazon_virtual_private_cloud_check_default_security_group_compliance,
	amazon_virtual_private_cloud_check_vpc_peering_routing_compliance,
	amazon_virtual_private_cloud_check_nacl_port22_compliance,
	amazon_virtual_private_cloud_check_security_group_admin_ports,
	amazon_virtual_private_cloud_check_vpc_flow_logs,
	aws_cloudtrail_check_cloudtrail_log_validation,
	aws_cloudtrail_check_cloudtrail_enabled,
	aws_cloudtrail_check_cloudtrail_s3_access_logging,
	aws_cloudtrail_check_cloudtrail_kms_encryption,
	aws_cloudtrail_check_cloudtrail_tagged,
	aws_cloudtrail_check_cloudtrail_multiregion,
	aws_cloudtrail_check_cloudtrail_encryption
];

export default allTests;
