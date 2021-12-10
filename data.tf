# # ---------------------------------------------------------------------------------------------------------------------#
# Get the list of AWS Availability Zones available in this region
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_availability_zone" "all" {
  for_each = toset(data.aws_availability_zones.available.names)
  name = each.key
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Get the name of the region where the Terraform deployment is running
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_region" "current" {}

# # ---------------------------------------------------------------------------------------------------------------------#
# Get the effective Account ID, User ID, and ARN in which Terraform is authorized.
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_caller_identity" "current" {}

# # ---------------------------------------------------------------------------------------------------------------------#
# Get the Account ID of the AWS ELB Service Account for the purpose of permitting in S3 bucket policy.
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_elb_service_account" "current" {}

# # ---------------------------------------------------------------------------------------------------------------------#
# Get AWS Inspector rules available in this region
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_inspector_rules_packages" "available" {}


# # ---------------------------------------------------------------------------------------------------------------------#
# Get the ID of CloudFront origin request policy
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_cloudfront_origin_request_policy" "s3" {
  name = "Managed-CORS-S3Origin"
}
data "aws_cloudfront_origin_request_policy" "custom" {
  name = "Managed-CORS-CustomOrigin"
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Get the ID of CloudFront cache policy.
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_cloudfront_cache_policy" "s3" {
  name = "Managed-CachingOptimizedForUncompressedObjects"
}
data "aws_cloudfront_cache_policy" "custom" {
  name = "Managed-CachingOptimized"
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Get get the latest ID of a registered AMI linux distro by owner and version
# # ---------------------------------------------------------------------------------------------------------------------#
data "aws_ami" "distro" {
  most_recent = true
  // owners      = ["099720109477"] # ubuntu
  owners      = ["136693071363"] # debian

  filter {
    name   = "name"
    // values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-arm64-server-*"] # ubuntu
    values = ["debian-11-arm64*"] # debian
  }
}


# # ---------------------------------------------------------------------------------------------------------------------#
# Variables for user_data templates generation
# # ---------------------------------------------------------------------------------------------------------------------#
data "template_file" "user_data" {
  for_each = var.ec2
  template = file("./user_data/${each.key}")

  vars = {

    INSTANCE_NAME = "${each.key}"
    CIDR = "${aws_vpc.this.cidr_block}"
    RESOLVER = "${cidrhost(aws_vpc.this.cidr_block, 2)}"
    AWS_DEFAULT_REGION = "${data.aws_region.current.name}"

    ALB_DNS_NAME = "${aws_lb.this["outer"].dns_name}"

    CODECOMMIT_APP_REPO = "codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.app.repository_name}"
    CODECOMMIT_SERVICES_REPO = "codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.services.repository_name}"
        
    EXTRA_PACKAGES_DEB = "nfs-common unzip git patch python3-pip acl attr imagemagick snmp gpg"
    EXCLUDE_PACKAGES_DEB = "apache2* *apcu-bc"
    NODE_VERSION = "${var.app["node_version"]}"

    VERSION = "2"
    DOMAIN = "${var.app["domain"]}"
    STAGING_DOMAIN = "${var.app["staging_domain"]}"
    BRAND = "${var.app["brand"]}"
    OS_USER = "${var.app["os_user"]}"

    ADMIN_EMAIL = "${var.app["admin_email"]}"
    WEB_ROOT_PATH = "/var/www/${var.app["brand"]}"
    TIMEZONE = "${var.app["timezone"]}"
    X2F1_HEADER = "${random_uuid.this.result}"
    HEALTH_CHECK_LOCATION = "${random_string.this["health_check"].result}"
  }
}