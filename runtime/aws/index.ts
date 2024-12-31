/* eslint-disable */
/**
 * This file is auto-generated by the "npm run generate-runtime-index" command.
 * Do not modify this file directly.
 */
import import0 from "./AWS CloudTrail/check-cloudtrail-bucket-access.js";
import import1 from "./AWS CloudTrail/check-cloudtrail-enabled.js";
import import2 from "./AWS CloudTrail/check-cloudtrail-encryption.js";
import import3 from "./AWS CloudTrail/check-cloudtrail-kms-encryption.js";
import import4 from "./AWS CloudTrail/check-cloudtrail-log-validation.js";
import import5 from "./AWS CloudTrail/check-cloudtrail-multiregion.js";
import import6 from "./AWS CloudTrail/check-cloudtrail-s3-access-logging.js";
import import7 from "./AWS CloudTrail/check-cloudtrail-tagged.js";
import import8 from "./AWS Config/check-config-enabled-all-regions.js";
import import9 from "./AWS Key Management Service/check-iam-kms-decrypt-policy.js";
import import10 from "./AWS Key Management Service/check-inline-policy-kms-decrypt.js";
import import11 from "./AWS Key Management Service/check-kms-key-rotation.js";
import import12 from "./AWS Key Management Service/check-kms-keys-deletion-status.js";
import import13 from "./AWS Key Management Service/check-kms-public-access.js";
import import14 from "./AWS Security Hub/check-security-hub.js";
import import15 from "./Amazon CloudWatch/aws_cloudwatch_alarm_action_check.js";
import import16 from "./Amazon CloudWatch/aws_cloudwatch_alarm_action_enabled.js";
import import17 from "./Amazon CloudWatch/aws_cloudwatch_cloudtrail.js";
import import18 from "./Amazon CloudWatch/aws_cloudwatch_cmk.js";
import import19 from "./Amazon CloudWatch/aws_cloudwatch_config.js";
import import20 from "./Amazon CloudWatch/aws_cloudwatch_console_auth.js";
import import21 from "./Amazon CloudWatch/aws_cloudwatch_log_group_retention.js";
import import22 from "./Amazon CloudWatch/aws_cloudwatch_monitoring_iam_policies.js";
import import23 from "./Amazon CloudWatch/aws_cloudwatch_monitoring_root_account.js";
import import24 from "./Amazon CloudWatch/aws_cloudwatch_monitoring_signin_mfa.js";
import import25 from "./Amazon CloudWatch/aws_cloudwatch_monitoring_unauthorized_api_calls.js";
import import26 from "./Amazon CloudWatch/aws_cloudwatch_nacl_monitoring.js";
import import27 from "./Amazon CloudWatch/aws_cloudwatch_network_gateway.js";
import import28 from "./Amazon CloudWatch/aws_cloudwatch_org_changes_monitored.js";
import import29 from "./Amazon CloudWatch/aws_cloudwatch_route_table.js";
import import30 from "./Amazon CloudWatch/aws_cloudwatch_s3_policy_change.js";
import import31 from "./Amazon CloudWatch/aws_cloudwatch_security_group.js";
import import32 from "./Amazon CloudWatch/aws_cloudwatch_vpc_changes_monitored.js";
import import33 from "./Amazon Elastic Compute Cloud (EC2)/aws_autoscaling_elb_healthcheck_required.js";
import import34 from "./Amazon Elastic Compute Cloud (EC2)/aws_autoscaling_launch_template.js";
import import35 from "./Amazon Elastic Compute Cloud (EC2)/aws_autoscaling_multiple_instance_types.js";
import import36 from "./Amazon Elastic Compute Cloud (EC2)/aws_autoscaling_no_public_ip.js";
import import37 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_ami_encryption.js";
import import38 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_ami_public_acees.js";
import import39 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_autoscaling_propagate_tag.js";
import import40 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_default_security_group.js";
import import41 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_detailed_monitoring.js";
import import42 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_imdsv2.js";
import import43 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_launch_template_imdsv2.js";
import import44 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_launch_template_public_ip.js";
import import45 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_multiple_eni.js";
import import46 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_no_public_ip.js";
import import47 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_no_secrets_in_user_data.js";
import import48 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_subnet_auto_assign_public_ip.js";
import import49 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_systems_manager.js";
import import50 from "./Amazon Elastic Compute Cloud (EC2)/aws_ec2_vpc_endpoint.js";
import import51 from "./Amazon Elastic Compute Cloud (EC2)/aws_security_group_authorized_ports.js";
import import52 from "./Amazon Elastic Compute Cloud (EC2)/aws_security_group_high_risk_ports.js";
import import53 from "./Amazon Elastic Compute Cloud (EC2)/aws_transit_gateway_auto_accept_disabled.js";
import import54 from "./Amazon Elastic Compute Cloud (EC2)/check-ec2-instance-age.js";
import import55 from "./Amazon Elastic Compute Cloud (EC2)/check-stopped-instances.js";
import import56 from "./Amazon Elastic Compute Cloud (EC2)/check-unused-enis.js";
import import57 from "./Amazon Elastic Container Registry/check-ecr-image-scanning.js";
import import58 from "./Amazon Elastic Container Registry/check-ecr-lifecycle-policy.js";
import import59 from "./Amazon Elastic Container Registry/check-ecr-tag-immutability.js";
import import60 from "./Amazon Elastic Container Registry/check-ecs-container-insights.js";
import import61 from "./Amazon Elastic Container Registry/check-ecs-container-readonly-root.js";
import import62 from "./Amazon Elastic File System/aws_efs_access_points_enforce_root_directory.js";
import import63 from "./Amazon Elastic File System/aws_efs_access_points_enforce_user_identity.js";
import import64 from "./Amazon Elastic File System/aws_efs_file_system_kms_encryption.js";
import import65 from "./Amazon Elastic File System/aws_efs_mount_targets_not_public.js";
import import66 from "./Amazon Identity and Access Management/aws_iam_access_analyzer.js";
import import67 from "./Amazon Identity and Access Management/aws_iam_account_password_policy.js";
import import68 from "./Amazon Identity and Access Management/aws_iam_centralized_management.js";
import import69 from "./Amazon Identity and Access Management/aws_iam_cloudshell_access.js";
import import70 from "./Amazon Identity and Access Management/aws_iam_instance_roles.js";
import import71 from "./Amazon Identity and Access Management/aws_iam_no_full_admin.js";
import import72 from "./Amazon Identity and Access Management/aws_iam_no_initial_access_keys.js";
import import73 from "./Amazon Identity and Access Management/aws_iam_no_wildcard_actions.js";
import import74 from "./Amazon Identity and Access Management/aws_iam_password_reuse_prevention.js";
import import75 from "./Amazon Identity and Access Management/aws_iam_support_role.js";
import import76 from "./Amazon Identity and Access Management/aws_iam_users_no_direct_policies.js";
import import77 from "./Amazon Identity and Access Management/aws_iam_users_permissions_through_group.js";
import import78 from "./Amazon Identity and Access Management/check-access-key-rotation.js";
import import79 from "./Amazon Identity and Access Management/check-expired-certificates.js";
import import80 from "./Amazon Identity and Access Management/check-iam-access-keys.js";
import import81 from "./Amazon Identity and Access Management/check-iam-mfa.js";
import import82 from "./Amazon Identity and Access Management/check-unused-credentials.js";
import import83 from "./Amazon Relational Database Service/check-aurora-access-key-rotation.js";
import import84 from "./Amazon Relational Database Service/check-aurora-audit-logging.js";
import import85 from "./Amazon Relational Database Service/check-aurora-backtracking.js";
import import86 from "./Amazon Relational Database Service/check-aurora-backup-compliance.js";
import import87 from "./Amazon Relational Database Service/check-aurora-encryption-in-transit.js";
import import88 from "./Amazon Relational Database Service/check-aurora-encryption.js";
import import89 from "./Amazon Relational Database Service/check-aurora-iam-roles-and-policies.js";
import import90 from "./Amazon Relational Database Service/check-aurora-least-privilege.js";
import import91 from "./Amazon Relational Database Service/check-aurora-mysql-cloudwatch-logs.js";
import import92 from "./Amazon Relational Database Service/check-aurora-postgres-cloudwatch-logs.js";
import import93 from "./Amazon Relational Database Service/check-neptune-audit-logs.js";
import import94 from "./Amazon Relational Database Service/check-neptune-automated-backups.js";
import import95 from "./Amazon Relational Database Service/check-neptune-cluster-encryption.js";
import import96 from "./Amazon Relational Database Service/check-neptune-copy-tags-to-snapshot.js";
import import97 from "./Amazon Relational Database Service/check-neptune-deletion-protection.js";
import import98 from "./Amazon Relational Database Service/check-neptune-iam-auth.js";
import import99 from "./Amazon Relational Database Service/check-neptune-snapshots-encryption.js";
import import100 from "./Amazon Relational Database Service/check-rds-access-control-authentication.js";
import import101 from "./Amazon Relational Database Service/check-rds-auto-minor-version-upgrade.js";
import import102 from "./Amazon Relational Database Service/check-rds-automated-backups.js";
import import103 from "./Amazon Relational Database Service/check-rds-backup-enabled.js";
import import104 from "./Amazon Relational Database Service/check-rds-cloudwatch-logs.js";
import import105 from "./Amazon Relational Database Service/check-rds-cluster-deletion-protection.js";
import import106 from "./Amazon Relational Database Service/check-rds-cluster-encryption.js";
import import107 from "./Amazon Relational Database Service/check-rds-cluster-iam-auth.js";
import import108 from "./Amazon Relational Database Service/check-rds-cluster-multi-az.js";
import import109 from "./Amazon Relational Database Service/check-rds-cluster-tag.js";
import import110 from "./Amazon Relational Database Service/check-rds-custom-admin-username.js";
import import111 from "./Amazon Relational Database Service/check-rds-database-security.js";
import import112 from "./Amazon Relational Database Service/check-rds-default-ports.js";
import import113 from "./Amazon Relational Database Service/check-rds-deletion-protection.js";
import import114 from "./Amazon Relational Database Service/check-rds-encryption-at-rest.js";
import import115 from "./Amazon Relational Database Service/check-rds-encryption-in-transit.js";
import import116 from "./Amazon Relational Database Service/check-rds-enhanced-monitoring.js";
import import117 from "./Amazon Relational Database Service/check-rds-event-notifications.js";
import import118 from "./Amazon Relational Database Service/check-rds-event-subscription-parameter-group.js";
import import119 from "./Amazon Relational Database Service/check-rds-event-subscriptions.js";
import import120 from "./Amazon Relational Database Service/check-rds-iam-auth.js";
import import121 from "./Amazon Relational Database Service/check-rds-in-vpc.js";
import import122 from "./Amazon Relational Database Service/check-rds-instances-in-vpc.js";
import import123 from "./Amazon Relational Database Service/check-rds-monitoring-logging.js";
import import124 from "./Amazon Relational Database Service/check-rds-multi-az.js";
import import125 from "./Amazon Relational Database Service/check-rds-password-rotation.js";
import import126 from "./Amazon Relational Database Service/check-rds-postgres-cloudwatch-logs.js";
import import127 from "./Amazon Relational Database Service/check-rds-public-access.js";
import import128 from "./Amazon Relational Database Service/check-rds-security-group-event-notifications.js";
import import129 from "./Amazon Relational Database Service/check-rds-security-groups-configured.js";
import import130 from "./Amazon Relational Database Service/check-rds-security-groups.js";
import import131 from "./Amazon Relational Database Service/check-rds-snapshot-encryption.js";
import import132 from "./Amazon Relational Database Service/check-rds-snapshots-private.js";
import import133 from "./Amazon Relational Database Service/check-rds-tag-copy-compliance.js";
import import134 from "./Amazon Relational Database Service/check-vpc-exists.js";
import import135 from "./Amazon Simple Storage Service (Amazon S3)/aws_s3_http_access_deny.js";
import import136 from "./Amazon Simple Storage Service (Amazon S3)/aws_s3_mfa_delete_enabled.js";
import import137 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-access-point-block-public-access.js";
import import138 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-block-public-access.js";
import import139 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-acl-compliance.js";
import import140 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-external-access.js";
import import141 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-lifecycle-configuration.js";
import import142 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-bucket-logging.js";
import import143 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-data-discovery-compliance.js";
import import144 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-deny-http-access.js";
import import145 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-mfa-delete.js";
import import146 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-object-level-logging.js";
import import147 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-object-read-logging.js";
import import148 from "./Amazon Simple Storage Service (Amazon S3)/check-s3-ssl-required.js";
import import149 from "./Amazon Virtual Private Cloud/check-default-security-group-compliance.js";
import import150 from "./Amazon Virtual Private Cloud/check-nacl-port22-compliance.js";
import import151 from "./Amazon Virtual Private Cloud/check-security-group-admin-ports.js";
import import152 from "./Amazon Virtual Private Cloud/check-vpc-flow-logs.js";
import import153 from "./Amazon Virtual Private Cloud/check-vpc-peering-routing-compliance.js";

export default [
    import0,
    import1,
    import2,
    import3,
    import4,
    import5,
    import6,
    import7,
    import8,
    import9,
    import10,
    import11,
    import12,
    import13,
    import14,
    import15,
    import16,
    import17,
    import18,
    import19,
    import20,
    import21,
    import22,
    import23,
    import24,
    import25,
    import26,
    import27,
    import28,
    import29,
    import30,
    import31,
    import32,
    import33,
    import34,
    import35,
    import36,
    import37,
    import38,
    import39,
    import40,
    import41,
    import42,
    import43,
    import44,
    import45,
    import46,
    import47,
    import48,
    import49,
    import50,
    import51,
    import52,
    import53,
    import54,
    import55,
    import56,
    import57,
    import58,
    import59,
    import60,
    import61,
    import62,
    import63,
    import64,
    import65,
    import66,
    import67,
    import68,
    import69,
    import70,
    import71,
    import72,
    import73,
    import74,
    import75,
    import76,
    import77,
    import78,
    import79,
    import80,
    import81,
    import82,
    import83,
    import84,
    import85,
    import86,
    import87,
    import88,
    import89,
    import90,
    import91,
    import92,
    import93,
    import94,
    import95,
    import96,
    import97,
    import98,
    import99,
    import100,
    import101,
    import102,
    import103,
    import104,
    import105,
    import106,
    import107,
    import108,
    import109,
    import110,
    import111,
    import112,
    import113,
    import114,
    import115,
    import116,
    import117,
    import118,
    import119,
    import120,
    import121,
    import122,
    import123,
    import124,
    import125,
    import126,
    import127,
    import128,
    import129,
    import130,
    import131,
    import132,
    import133,
    import134,
    import135,
    import136,
    import137,
    import138,
    import139,
    import140,
    import141,
    import142,
    import143,
    import144,
    import145,
    import146,
    import147,
    import148,
    import149,
    import150,
    import151,
    import152,
    import153
];