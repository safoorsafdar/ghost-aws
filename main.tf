/////////////////////////////////////////////////[ AWS BUDGET NOTIFICATION ]//////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create alert when your budget thresholds are forecasted to exceed
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_budgets_budget" "all" {
  name              = "${var.app["brand"]}-budget-monthly-forecasted"
  budget_type       = "COST"
  limit_amount      = "100"
  limit_unit        = "USD"
  time_unit         = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.app["admin_email"]]
  }
}


///////////////////////////////////////////////////[ RANDOM STRING GENERATOR ]////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Generate random uuid string that is intended to be used as unique identifier
# # ---------------------------------------------------------------------------------------------------------------------#
resource "random_uuid" "this" {
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Generate random passwords
# # ---------------------------------------------------------------------------------------------------------------------#
resource "random_password" "this" {
  for_each         = toset(["rds"])
  length           = 16
  lower            = true
  upper            = true
  number           = true
  special          = true
  override_special = "%*?"
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Generate random string
# # ---------------------------------------------------------------------------------------------------------------------#
resource "random_string" "this" {
  for_each       = toset(["health_check"])
  length         = (7)
  lower          = true
  number         = true
  special        = false
  upper          = false
}

////////////////////////////////////////////////////////[ VPC NETWORKING ]////////////////////////////////////////////////

## ---------------------------------------------------------------------------------------------------------------------#
# Create our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_vpc" "this" {
  cidr_block           = var.app["cidr_block"]
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.app["brand"]}-vpc"
    Owner = "${var.app["admin_email"]}"
  }
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create subnets for each AZ in our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_subnet" "this" {
  for_each                = data.aws_availability_zone.all
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(aws_vpc.this.cidr_block, 4, var.az_number[each.value.name_suffix])
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.app["brand"]}-subnet"
    Owner = "${var.app["admin_email"]}"
  }
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create RDS subnet group in our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_db_subnet_group" "this" {
  name       = "${var.app["brand"]}-db-subnet"
  description = "${var.app["brand"]} RDS Subnet"
  subnet_ids = values(aws_subnet.this).*.id
  tags = {
    Name = "${var.app["brand"]}-db-subnet"
    Owner = "${var.app["admin_email"]}"
  }
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create internet gateway in our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags = {
    Name = "${var.app["brand"]}-igw"
    Owner = "${var.app["admin_email"]}"
  }
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create route table in our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_route" "this" {
  route_table_id         = aws_vpc.this.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

## ---------------------------------------------------------------------------------------------------------------------#
# Assign AZ subnets to route table in our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_route_table_association" "this" {
  for_each       = aws_subnet.this
  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_vpc.this.main_route_table_id
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create DHCP options in our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_vpc_dhcp_options" "this" {
  domain_name          = "${data.aws_region.current.name}.compute.internal"
  domain_name_servers  = ["AmazonProvidedDNS"]
  tags = {
    Name = "${var.app["brand"]}-dhcp"
    Owner = "${var.app["admin_email"]}"
  }
}

## ---------------------------------------------------------------------------------------------------------------------#
# Assign DHCP options to our dedicated VPC
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_vpc_dhcp_options_association" "this" {
  vpc_id          = aws_vpc.this.id
  dhcp_options_id = aws_vpc_dhcp_options.this.id
}

////////////////////////////////////////////////////[ SNS SUBSCRIPTION TOPIC ]////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create SNS topic and email subscription (confirm email right after resource creation)
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_sns_topic" "default" {
  name = "${var.app["brand"]}-email-alerts"
}
resource "aws_sns_topic_subscription" "default" {
  topic_arn = aws_sns_topic.default.arn
  protocol  = "email"
  endpoint  = var.app["admin_email"]
}

///////////////////////////////////////////////////////[ SECURITY GROUPS ]////////////////////////////////////////////////

## ---------------------------------------------------------------------------------------------------------------------#
# Create Security Groups
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_security_group" "this" {
  for_each    = local.security_group
  name        = "${var.app["brand"]}-${each.key}"
  description = "${each.key} security group"
  vpc_id      = aws_vpc.this.id

  tags = {
    Name = "${var.app["brand"]}-${each.key}"
    Owner = "${var.app["admin_email"]}"
  }
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create Security Rules for Security Groups
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_security_group_rule" "this" {
   for_each =  local.security_rule
   type             = lookup(each.value, "type", null)
   description      = lookup(each.value, "description", null)
   from_port        = lookup(each.value, "from_port", null)
   to_port          = lookup(each.value, "to_port", null)
   protocol         = lookup(each.value, "protocol", null)
   cidr_blocks      = lookup(each.value, "cidr_blocks", null)
   source_security_group_id = lookup(each.value, "source_security_group_id", null)
   security_group_id = each.value.security_group_id
}

///////////////////////////////////////////////////[ AWS CERTIFICATE MANAGER ]////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create and validate ssl certificate for domain and subdomains
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_acm_certificate" "default" {
  domain_name               = "${var.app["domain"]}"
  subject_alternative_names = ["*.${var.app["domain"]}"]
  validation_method         = "EMAIL"

  lifecycle {
    create_before_destroy   = true
  }
}

resource "aws_acm_certificate_validation" "default" {
  certificate_arn = aws_acm_certificate.default.arn
}

////////////////////////////////////////////////////////[ CODECOMMIT ]////////////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Setup Git Global user information
# # ---------------------------------------------------------------------------------------------------------------------#
resource "null_resource" "git_user_setup" {
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = <<EOF
        git config --global user.email "${var.app["git_user_email"]}"
        git config --global user.name "${var.app["git_user_name"]}"
    EOF
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CodeCommit repository for application code
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_codecommit_repository" "app" {
  repository_name = var.app["domain"]
  description     = "Ghost code for ${var.app["domain"]}"
    tags = {
    Name = "${var.app["brand"]}-${var.app["domain"]}"
    Owner = "${var.app["admin_email"]}"
  }
  provisioner "local-exec" {
  interpreter = ["/bin/bash", "-c"]
  command = <<EOF
          git clone ${var.app["source"]} /tmp/ghost
          cd /tmp/ghost
          git remote add origin codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.app.repository_name}
          git branch -m main
          git push codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.app.repository_name} main
          rm -rf /tmp/ghost
EOF
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CodeCommit repository for services configuration
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_codecommit_repository" "services" {
  repository_name = "${var.app["brand"]}-services-config"
  description     = "EC2 linux and services configurations"
  tags = {
    Name = "${var.app["brand"]}-services-config"
    Owner = "${var.app["admin_email"]}"
  }
  provisioner "local-exec" {
  interpreter = ["/bin/bash", "-c"]
  command = <<EOF
          cd ${abspath(path.root)}/services/nginx
          git init
          git commit --allow-empty -m "main branch"
          git branch -m main
          git push codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.services.repository_name} main

          git branch -m nginx_frontend
          git add .
          git commit -m "nginx_ec2_config"
          git push codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.services.repository_name} nginx_frontend
		      
          git branch -m nginx_staging
          git push codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.services.repository_name} nginx_staging
          rm -rf .git

EOF
  }
}


////////////////////////////////////////////////////////[ CLOUDFRONT ]////////////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudFront distribution with S3 origin
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudfront_origin_access_identity" "this" {
  comment = "CloudFront origin access identity"
}

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  is_ipv6_enabled     = true
  web_acl_id          = aws_wafv2_web_acl.this.arn
  price_class         = "PriceClass_100"
  comment             = "${var.app["domain"]} assets"
  
  origin {
    domain_name = aws_s3_bucket.this["media"].bucket_regional_domain_name
    origin_id   = "${var.app["domain"]}-media-assets"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.this.cloudfront_access_identity_path
    }
	  
    custom_header {
      name  = "X-X2f1-Header"
      value = random_uuid.this.result
    }
  }
  
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${var.app["domain"]}-media-assets"

    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.s3.id
    cache_policy_id          = data.aws_cloudfront_cache_policy.s3.id

    viewer_protocol_policy = "https-only"

  }
  
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.this["system"].bucket_domain_name
    prefix          = "${var.app["brand"]}-cloudfront-logs"
  }
  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version = "TLSv1.2_2021"
  }
  
  tags = {
    Name = "${var.app["brand"]}-cloudfront-production"
    Owner = "${var.app["admin_email"]}"
  }
}



/////////////////////////////////////////////////////[ EC2 INSTANCE PROFILE ]/////////////////////////////////////////////

## ---------------------------------------------------------------------------------------------------------------------#
# Create EC2 service role
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_iam_role" "ec2" {
  for_each = var.ec2
  name = "${var.app["brand"]}-EC2InstanceRole-${each.key}-${data.aws_region.current.name}"
  description = "Allows EC2 instances to call AWS services on your behalf"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

## ---------------------------------------------------------------------------------------------------------------------#
# Attach policies to EC2 service role
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_iam_role_policy_attachment" "ec2" {
  for_each = { for policy in [ for role,policy in setproduct(keys(var.ec2),var.ec2_instance_profile_policy): { role = policy[0] , policy = policy[1]} ] : "${policy.role}-${policy.policy}" => policy }
  role       = aws_iam_role.ec2[each.value.role].name
  policy_arn = each.value.policy
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create inline policy for EC2 service role to publish sns message
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_iam_role_policy" "sns_publish" {
  for_each = var.ec2
  name = "EC2ProfileSNSPublishPolicy${title(each.key)}"
  role = aws_iam_role.ec2[each.key].id

  policy = jsonencode({
  Version = "2012-10-17",
  Statement = [
    {
      Sid    = "EC2ProfileSNSPublishPolicy${each.key}",
      Effect = "Allow",
      Action = [
            "sns:Publish"
      ],
      Resource = aws_sns_topic.default.arn
 }]
})
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create inline policy for EC2 service role to limit CodeCommit access
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_iam_role_policy" "codecommit_access" {
  for_each = var.ec2
  name = "PolicyForCodeCommitAccess${title(each.key)}"
  role = aws_iam_role.ec2[each.key].id

  policy = jsonencode({
  Version = "2012-10-17",
  Statement = [
    {
      Sid    = "codecommitaccessapp${each.key}",
      Effect = "Allow",
      Action = [
            "codecommit:Get*",
            "codecommit:List*",
            "codecommit:Merge*",
            "codecommit:GitPull",
            "codecommit:GitPush"
      ],
      Resource = aws_codecommit_repository.app.arn
      Condition = {
                StringEqualsIfExists = {
                    "codecommit:References" = [(each.key == "admin" || each.key == "frontend" ? "refs/heads/main" : (each.key == "staging" ? "refs/heads/staging" : "refs/heads/build"))]
    }
   }
},
     {
      Sid    = "codecommitaccessservices${each.key}", 
      Effect = "Allow",
      Action = [
            "codecommit:Get*",
            "codecommit:List*",
            "codecommit:Describe*",
            "codecommit:GitPull"
      ],
      Resource = aws_codecommit_repository.services.arn
    }]
})
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create EC2 Instance Profile
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_iam_instance_profile" "ec2" {
  for_each = var.ec2
  name     = "${var.app["brand"]}-EC2InstanceProfile-${each.key}"
  role     = aws_iam_role.ec2[each.key].name
}

//////////////////////////////////////////////////////////[ S3 BUCKET ]///////////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create S3 bucket
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_s3_bucket" "this" {
  for_each      = var.s3
  bucket        = "${var.app["brand"]}-${each.key}-storage"
  force_destroy = true
  acl           = "private"
  tags = {
    Name        = "${var.app["brand"]}-${each.key}-storage"
    Owner       = "${var.app["admin_email"]}"
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create IAM user for S3 bucket
# # ---------------------------------------------------------------------------------------------------------------------#	  
resource "aws_iam_user" "s3" {
  name = "${var.app["brand"]}-s3-media-production"
  tags = {
    Name = "${var.app["brand"]}-s3-media-production"
  }
}
	  
resource "aws_iam_access_key" "s3" {
  user = aws_iam_user.s3.name
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create policy for CloudFront and S3 user to limit S3 media bucket access
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_s3_bucket_policy" "media" {
   bucket = aws_s3_bucket.this["media"].id
   policy = jsonencode({
   Id = "PolicyForMediaStorageAccess"
   Statement = [
	  {
         Action = "s3:GetObject"
         Effect = "Allow"
         Principal = {
            AWS = aws_cloudfront_origin_access_identity.this.iam_arn
         }
         Resource = [
            "${aws_s3_bucket.this["media"].arn}/*.jpg",
            "${aws_s3_bucket.this["media"].arn}/*.jpeg",
            "${aws_s3_bucket.this["media"].arn}/*.png",
            "${aws_s3_bucket.this["media"].arn}/*.gif",
            "${aws_s3_bucket.this["media"].arn}/*.webp"
         ]
      }, 
      {
         Action = ["s3:PutObject"],
         Effect = "Allow"
         Principal = {
            AWS = [ aws_iam_user.s3.arn ]
         }
         Resource = [
            "${aws_s3_bucket.this["media"].arn}",
            "${aws_s3_bucket.this["media"].arn}/*"
         ]
         Condition = {
            StringEquals = {
                "aws:SourceVpc" = [ aws_vpc.this.id ]
         }
	}
      }, 
      {
         Action = ["s3:GetObject", "s3:GetObjectAcl"],
         Effect = "Allow"
         Principal = {
            AWS = [ aws_iam_user.s3.arn ]
         }
         Resource = [
            "${aws_s3_bucket.this["media"].arn}",
            "${aws_s3_bucket.this["media"].arn}/*"
         ]
      }, 
      {
         Action = ["s3:GetBucketLocation", "s3:ListBucket"],
         Effect = "Allow"
         Principal = {
            AWS = [ aws_iam_user.s3.arn ]
         }
         Resource = "${aws_s3_bucket.this["media"].arn}"
      }, 
	  ] 
	  Version = "2012-10-17"
   })
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create S3 bucket policy for ALB to write access logs
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_s3_bucket_policy" "system" {
  bucket = aws_s3_bucket.this["system"].id
  policy = jsonencode(
            {
  Id = "PolicyALBWriteLogs"
  Version = "2012-10-17"
  Statement = [
    {
      Action = [
        "s3:PutObject"
      ],
      Effect = "Allow"
      Resource = "arn:aws:s3:::${aws_s3_bucket.this["system"].id}/${var.app["brand"]}-alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      Principal = {
        AWS = [
          data.aws_elb_service_account.current.arn
        ]
      }
    }
  ]
}
)
}

//////////////////////////////////////////////////////////////[ RDS ]/////////////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create RDS parameter groups
# # ---------------------------------------------------------------------------------------------------------------------#		
resource "aws_db_parameter_group" "this" {
  for_each          = toset(var.rds["name"])
  name              = "${var.app["brand"]}-${each.key}-parameters"
  family            = "mariadb10.5"
  description       = "Parameter group for ${var.app["brand"]} ${each.key} database"
  tags = {
    Name = "${var.app["brand"]}-${each.key}-parameters"
    Owner       = "${var.app["admin_email"]}"
  }
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create RDS instance
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_db_instance" "this" {
  for_each               = toset(var.rds["name"])
  identifier             = "${var.app["brand"]}-${each.key}"
  allocated_storage      = var.rds["allocated_storage"]
  max_allocated_storage  = var.rds["max_allocated_storage"]
  storage_type           = var.rds["storage_type"] 
  engine                 = var.rds["engine"]
  engine_version         = var.rds["engine_version"]
  instance_class         = (each.key == "staging" ? var.rds["instance_class_staging"] : var.rds["instance_class"])
  multi_az               = (each.key == "staging" ? "false" : var.rds["multi_az"])
  name                   = "${var.app["brand"]}_${each.key}"
  username               = var.app["brand"]
  password               = random_password.this["rds"].result
  parameter_group_name   = aws_db_parameter_group.this[each.key].id
  skip_final_snapshot    = var.rds["skip_final_snapshot"]
  vpc_security_group_ids = [aws_security_group.this["rds"].id]
  db_subnet_group_name   = aws_db_subnet_group.this.name
  enabled_cloudwatch_logs_exports = [var.rds["enabled_cloudwatch_logs_exports"]]
  performance_insights_enabled    = var.rds["performance_insights_enabled"]
  copy_tags_to_snapshot           = var.rds["copy_tags_to_snapshot"]
  backup_retention_period         = var.rds["backup_retention_period"]
  delete_automated_backups        = var.rds["delete_automated_backups"]
  deletion_protection             = var.rds["deletion_protection"]
  tags = {
    Name = "${var.app["brand"]}-${each.key}"
    Owner       = "${var.app["admin_email"]}"
  }
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create RDS instance event subscription
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_db_event_subscription" "db_event_subscription" {
  name      = "${var.app["brand"]}-rds-event-subscription"
  sns_topic = aws_sns_topic.default.arn
  source_type = "db-instance"
  source_ids = [aws_db_instance.this["production"].id]
  event_categories = [
    "availability",
    "deletion",
    "failover",
    "failure",
    "low storage",
    "maintenance",
    "notification",
    "read replica",
    "recovery",
    "restoration",
    "configuration change"
  ]
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch CPU Utilization metrics and email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.app["brand"]} rds cpu utilization too high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "600"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "Average database CPU utilization over last 10 minutes too high"
  alarm_actions       = ["${aws_sns_topic.default.arn}"]
  ok_actions          = ["${aws_sns_topic.default.arn}"]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.this["production"].id
  }
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch Freeable Memory metrics and email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "rds_memory" {
  alarm_name          = "${var.app["brand"]} rds freeable memory too low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = "600"
  statistic           = "Average"
  threshold           = "1.0e+09"
  alarm_description   = "Average database freeable memory over last 10 minutes too low, performance may suffer"
  alarm_actions       = ["${aws_sns_topic.default.arn}"]
  ok_actions          = ["${aws_sns_topic.default.arn}"]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.this["production"].id
  }
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch Connections Anomaly metrics and email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "rds_connections_anomaly" {
  alarm_name          = "${var.app["brand"]} rds connections anomaly"
  comparison_operator = "GreaterThanUpperThreshold"
  evaluation_periods  = "5"
  threshold_metric_id = "e1"
  alarm_description   = "Database connection count anomaly detected"
  alarm_actions       = ["${aws_sns_topic.default.arn}"]
  ok_actions          = ["${aws_sns_topic.default.arn}"]
  
  insufficient_data_actions = []

  metric_query {
    id          = "e1"
    expression  = "ANOMALY_DETECTION_BAND(m1, 2)"
    label       = "DatabaseConnections (Expected)"
    return_data = "true"
  }

  metric_query {
    id          = "m1"
    return_data = "true"
    metric {
      metric_name = "DatabaseConnections"
      namespace   = "AWS/RDS"
      period      = "600"
      stat        = "Average"
      unit        = "Count"

      dimensions = {
        DBInstanceIdentifier = aws_db_instance.this["production"].id
      }
    }
  }
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch Max Connections metrics and email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "rds_max_connections" {
  alarm_name          = "${var.app["brand"]} rds connections over last 10 minutes is too high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "600"
  statistic           = "Average"
  threshold           = ceil((80 / 100) * var.max_connection_count[var.rds["instance_class"]])
  alarm_description   = "Average connections over last 10 minutes is too high"
  alarm_actions       = ["${aws_sns_topic.default.arn}"]
  ok_actions          = ["${aws_sns_topic.default.arn}"]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.this["production"].id
  }
}


/////////////////////////////////////////////////[ APPLICATION LOAD BALANCER ]////////////////////////////////////////////

## ---------------------------------------------------------------------------------------------------------------------#
# Create Application Load Balancers
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_lb" "this" {
  for_each           = var.alb
  name               = "${var.app["brand"]}-${each.key}-alb"
  internal           = each.value
  load_balancer_type = "application"
  drop_invalid_header_fields = true
  security_groups    = [aws_security_group.this[each.key].id]
  subnets            = values(aws_subnet.this).*.id
  access_logs {
    bucket  = aws_s3_bucket.this["system"].bucket
    prefix  = "${var.app["brand"]}-alb"
    enabled = true
  }
  tags = {
    Name = "${var.app["brand"]}-${each.key}-alb"
  }
}
## ---------------------------------------------------------------------------------------------------------------------#
# Create Target Groups for Load Balancers
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_lb_target_group" "this" {
  for_each    = var.ec2
  name        = "${var.app["brand"]}-${each.key}-target"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id
  health_check {
    path = "/healtz"
  }
}
## ---------------------------------------------------------------------------------------------------------------------#
# Create https:// listener for OUTER Load Balancer - forward to webnode
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_lb_listener" "outerhttps" {
  depends_on = [aws_acm_certificate_validation.default]
  load_balancer_arn = aws_lb.this["outer"].arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
  certificate_arn   = aws_acm_certificate.default.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["frontend"].arn
  }
}
## ---------------------------------------------------------------------------------------------------------------------#
# Create http:// listener for OUTER Load Balancer - redirect to https://
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_lb_listener" "outerhttp" {
  load_balancer_arn = aws_lb.this["outer"].arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch HTTP 5XX metrics and email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "httpcode_target_5xx_count" {
  alarm_name          = "${var.app["brand"]}-http-5xx-errors-from-target"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = "25"
  alarm_description   = "HTTPCode 5XX count for frontend instances over 25"
  alarm_actions       = ["${aws_sns_topic.default.arn}"]
  ok_actions          = ["${aws_sns_topic.default.arn}"]
  
  dimensions = {
    TargetGroup  = aws_lb_target_group.this["frontend"].arn
    LoadBalancer = aws_lb.this["outer"].arn
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch HTTP 5XX metrics and email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "httpcode_elb_5xx_count" {
  alarm_name          = "${var.app["brand"]}-http-5xx-errors-from-loadbalancer"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = "25"
  alarm_description   = "HTTPCode 5XX count for loadbalancer over 25"
  alarm_actions       = ["${aws_sns_topic.default.arn}"]
  ok_actions          = ["${aws_sns_topic.default.arn}"]
  
  dimensions = {
    LoadBalancer = aws_lb.this["outer"].arn
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch RequestCount metrics and email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "alb_rps" {
  alarm_name          = "${var.app["brand"]}-loadbalancer-rps"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RequestCount"
  namespace           = "AWS/ApplicationELB"
  period              = "120"
  statistic           = "Sum"
  threshold           = "5000"
  alarm_description   = "The number of requests processed over 2 minutes greater than 5000"
  alarm_actions       = ["${aws_sns_topic.default.arn}"]
  ok_actions          = ["${aws_sns_topic.default.arn}"]

  dimensions = {
    LoadBalancer = aws_lb.this["outer"].arn
  }
}

/////////////////////////////////////////////////////[ AUTOSCALING CONFIGURATION ]////////////////////////////////////////
# # ---------------------------------------------------------------------------------------------------------------------#
# Create Launch Template for Autoscaling Groups - user_data converted
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_launch_template" "this" {
  for_each = var.ec2
  name = "${var.app["brand"]}-${each.key}-ltpl"
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs { 
        volume_size = var.app["volume_size"]
        volume_type = "gp3"
    }
  }
  metadata_options {
    http_endpoint  = "enabled"
    http_tokens    = "required"
  }
  iam_instance_profile { 
      name = aws_iam_instance_profile.ec2[each.key].name 
  }
  image_id = data.aws_ami.distro.id
  instance_type = each.value
  monitoring { enabled = false }
  network_interfaces { 
    associate_public_ip_address = true
    security_groups = [aws_security_group.this["ec2"].id]
  }
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.app["brand"]}-${each.key}-ec2" 
      Owner = "${var.app["admin_email"]}"
    }
  }
  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "${var.app["brand"]}-${each.key}-ec2" 
      Owner = "${var.app["admin_email"]}"
    }
  }
  user_data = base64encode(data.template_file.user_data[each.key].rendered)
}
# # ---------------------------------------------------------------------------------------------------------------------#
# Create Autoscaling Groups
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_autoscaling_group" "this" {
  for_each = var.ec2
  name = "${var.app["brand"]}-${each.key}-asg"
  vpc_zone_identifier = values(aws_subnet.this).*.id
  desired_capacity    = var.asg["desired_capacity"]
  min_size            = var.asg["min_size"]
  max_size            = var.asg["max_size"]
  health_check_grace_period = var.asg["health_check_grace_period"]
  health_check_type         = var.asg["health_check_type"]
  target_group_arns  = [aws_lb_target_group.this[each.key].arn]
  launch_template {
    name    = aws_launch_template.this[each.key].name
    version = "$Latest"
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create Autoscaling groups actions for SNS topic email alerts
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_autoscaling_notification" "this" {
for_each = aws_autoscaling_group.this 
group_names = [
    aws_autoscaling_group.this[each.key].name
  ]

  notifications = [
    "autoscaling:EC2_INSTANCE_LAUNCH",
    "autoscaling:EC2_INSTANCE_TERMINATE",
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
    "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
  ]

  topic_arn = aws_sns_topic.default.arn
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create Autoscaling policy for scale-out
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_autoscaling_policy" "scaleout" {
  for_each               = var.ec2
  name                   = "${var.app["brand"]}-${each.key}-asp-out"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.this[each.key].name
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch alarm metric to execute Autoscaling policy for scale-out
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "scaleout" {
  for_each            = var.ec2
  alarm_name          = "${var.app["brand"]}-${each.key} scale-out alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.asp["evaluation_periods"]
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = var.asp["period"]
  statistic           = "Average"
  threshold           = var.asp["out_threshold"]
  dimensions = {
    AutoScalingGroupName  = aws_autoscaling_group.this[each.key].name
  }
  alarm_description = "${each.key} scale-out alarm - CPU exceeds ${var.asp["out_threshold"]} percent"
  alarm_actions     = [aws_autoscaling_policy.scaleout[each.key].arn]
}

## ---------------------------------------------------------------------------------------------------------------------#
# Create Autoscaling policy for scale-in
## ---------------------------------------------------------------------------------------------------------------------#
resource "aws_autoscaling_policy" "scalein" {
  for_each               = var.ec2
  name                   = "${var.app["brand"]}-${each.key}-asp-in"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.this[each.key].name
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create CloudWatch alarm metric to execute Autoscaling policy for scale-in
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_cloudwatch_metric_alarm" "scalein" {
  for_each            = var.ec2
  alarm_name          = "${var.app["brand"]}-${each.key} scale-in alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.asp["evaluation_periods"]
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = var.asp["period"]
  statistic           = "Average"
  threshold           = var.asp["in_threshold"]
  dimensions = {
    AutoScalingGroupName  = aws_autoscaling_group.this[each.key].name
  }
  alarm_description = "${each.key} scale-in alarm - CPU less than ${var.asp["in_threshold"]} percent"
  alarm_actions     = [aws_autoscaling_policy.scalein[each.key].arn]
}

////////////////////////////////////////////////////[ AMAZON SIMPLE EMAIL SERVICE ]///////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create SES user credentials, Configuration Set to stream SES metrics to CloudWatch
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_iam_user" "ses_smtp_user" {
  name = "${var.app["brand"]}-ses-smtp-user"
}
	
resource "aws_ses_email_identity" "ses_email_identity" {
  email = "${var.app["admin_email"]}"
}

resource "aws_iam_user_policy" "ses_smtp_user_policy" {
  name = "${var.app["brand"]}-ses-smtp-user-policy"
  user = aws_iam_user.ses_smtp_user.name
  
  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ],
        Resource : "*"
      }
    ]
  })
}

resource "aws_iam_access_key" "ses_smtp_user_access_key" {
  user = aws_iam_user.ses_smtp_user.name
}

resource "aws_ses_configuration_set" "this" {
  name = "${var.app["brand"]}-ses-events"
  reputation_metrics_enabled = true
  delivery_options {
    tls_policy = "Require"
  }
}

resource "aws_ses_event_destination" "cloudwatch" {
  name                   = "${var.app["brand"]}-ses-event-destination-cloudwatch"
  configuration_set_name = aws_ses_configuration_set.this.name
  enabled                = true
  matching_types         = ["bounce", "send", "complaint", "delivery"]

  cloudwatch_destination {
    default_value  = "default"
    dimension_name = "dimension"
    value_source   = "emailHeader"
  }
}

/////////////////////////////////////////////////////////[ SYSTEMS MANAGER ]//////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create SSM Parameter store for aws params
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_ssm_parameter" "infrastructure_params" {
  name        = "${var.app["brand"]}-aws-infrastructure-params"
  description = "Parameters for AWS infrastructure"
  type        = "String"
  value       = <<EOF

    DATABASE_ENDPOINT="${aws_db_instance.this["production"].endpoint}"
    DATABASE_INSTANCE_NAME="${aws_db_instance.this["production"].name}"
    DATABASE_USER_NAME="${aws_db_instance.this["production"].username}"
    DATABASE_PASSWORD='${random_password.this["rds"].result}'
	
    OUTER_ALB_DNS_NAME="${aws_lb.this["outer"].dns_name}"

    CLOUDFRONT_ADDRESS=${aws_cloudfront_distribution.this.domain_name}

    CODECOMMIT_APP_REPO="codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.app.repository_name}"
    CODECOMMIT_SERVICES_REPO="codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.services.repository_name}"
	
    SES_KEY=${aws_iam_access_key.ses_smtp_user_access_key.id}
    SES_SECRET=${aws_iam_access_key.ses_smtp_user_access_key.secret}
    SES_PASSWORD=${aws_iam_access_key.ses_smtp_user_access_key.ses_smtp_password_v4}


    HTTP_X_HEADER="${random_uuid.this.result}"

EOF

  tags = {
    Name = "${var.app["brand"]}-aws-infrastructure-params"
    Owner = "${var.app["admin_email"]}"
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create SSM Parameter configuration file for CloudWatch Agent
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_ssm_parameter" "cloudwatch_agent_config" {
  for_each    = var.ec2
  name        = "amazon-cloudwatch-agent-${each.key}.json"
  description = "Configuration file for CloudWatch agent at ${each.key}"
  type        = "String"
  value       = <<EOF
{
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
            {
                "file_path": "/var/log/nginx/error.log",
                "log_group_name": "${var.app["brand"]}_nginx_error_logs",
                "log_stream_name": "${each.key}-{instance_id}-{ip_address}"
            },
            %{ if each.key == "frontend" || each.key == "staging" ~}
            {
                "file_path": "/var/www/${var.app["brand"]}/content/logs/${var.app["brand"]}.log",
                "log_group_name": "${var.app["brand"]}_access_logs",
                "log_stream_name": "${each.key}-{instance_id}-{ip_address}"
            },
            {
                "file_path": "/var/www/${var.app["brand"]}/content/logs/${var.app["brand"]}.error.log",
                "log_group_name": "${var.app["brand"]}_app_error_logs",
                "log_stream_name": "${each.key}-{instance_id}-{ip_address}"
            },
            %{ endif ~}
            {
                "file_path": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log",
                "log_group_name": "${var.app["brand"]}_cloudwatch_agent_log",
                "log_stream_name": "${each.key}-{instance_id}-{ip_address}"
            },
            {
                "file_path": "/var/log/apt/history.log",
                "log_group_name": "${var.app["brand"]}_system_apt_history",
                "log_stream_name": "${each.key}-{instance_id}-{ip_address}"
            },
            {
                "file_path": "/var/log/syslog",
                "log_group_name": "${var.app["brand"]}_system_syslog",
                "log_stream_name": "${each.key}-{instance_id}-{ip_address}"
            }
            ]
          }
        },
        "log_stream_name": "${var.app["domain"]}",
        "force_flush_interval" : 60
      }
}
EOF

  tags = {
    Name = "amazon-cloudwatch-agent-${each.key}.json"
    Owner = "${var.app["admin_email"]}"
  }
}

# # ---------------------------------------------------------------------------------------------------------------------#
# Create SSM Document runShellScript to install ghost, push to codecommit, init git
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_ssm_document" "install_ghost" {
  name          = "${var.app["brand"]}-install-ghost-push-codecommit"
  document_type = "Command"
  document_format = "YAML"
  target_type   = "/AWS::EC2::Instance"
  content = <<EOT
---
schemaVersion: "2.2"
description: "Configure git, install ghost, push to codecommit"
parameters:
mainSteps:
- action: "aws:runShellScript"
  name: "${var.app["brand"]}InstallGhostPushCodecommit"
  inputs:
    runCommand:
    - |-
      #!/bin/bash
      cd /var/www/${var.app["brand"]}

      mv /var/www/${var.app["brand"]}/config.example.js /var/www/${var.app["brand"]}/config.production.js
      sed -i "s/__DB_HOST__/${aws_db_instance.this["production"].endpoint}/" /var/www/${var.app["brand"]}/config.production.js
      sed -i "s/__DB_DATABASE__/${aws_db_instance.this["production"].name}/" /var/www/${var.app["brand"]}/config.production.js
      sed -i "s/__DB_USER__/${aws_db_instance.this["production"].username}/" /var/www/${var.app["brand"]}/config.production.js
      sed -i "s/__DB_PASS__/${random_password.this["rds"].result}/" /var/www/${var.app["brand"]}/config.production.js
      
      
      sed -i "s/__SES_HOST__/email-smtp.${data.aws_region.current.name}.amazonaws.com/" /var/www/${var.app["brand"]}/config.production.js
      sed -i "s/__SES_ACCESS_KEY__/${aws_iam_access_key.ses_smtp_user_access_key.id}/" /var/www/${var.app["brand"]}/config.production.js
      sed -i "s/__SES_SEC_KEY__/${aws_iam_access_key.ses_smtp_user_access_key.ses_smtp_password_v4}/" /var/www/${var.app["brand"]}/config.production.js

      su ${var.app["os_user"]} -s /bin/bash -c "yarn setup"
      
      ## installation check
      if [[ $? -ne 0 ]]; then
      echo
      echo "Installation error - check command output log"
      exit 1
      fi
      if [ ! -f /var/www/${var.app["brand"]}/config.production.js ]; then
      echo "Installation error - config.js not available"
      exit 1
      fi
      git add . -A
      git commit -m ${var.app["brand"]}-init-$(date +'%y%m%d-%H%M%S')
      git remote add origin codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.app.repository_name}
      git branch -m main
      git push codecommit::${data.aws_region.current.name}://${aws_codecommit_repository.app.repository_name} main
EOT
}


///////////////////////////////////////////////////////[ AWS WAFv2 RULES ]////////////////////////////////////////////////

# # ---------------------------------------------------------------------------------------------------------------------#
# Create AWS WAFv2 rules
# # ---------------------------------------------------------------------------------------------------------------------#
resource "aws_wafv2_web_acl" "this" {
  name        = "${var.app["brand"]}-WAF-Protections"
  provider    = aws.useast1
  scope       = "CLOUDFRONT"
  description = "${var.app["brand"]}-WAF-Protections"

  default_action {
    allow {
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name = "${var.app["brand"]}-WAF-Protections"
    sampled_requests_enabled = true
  }

  rule {
    name     = "${var.app["brand"]}-Cloudfront-WAF-media-Protection-rate-based"
    priority = 0

    action {
      count {}
    }

    statement {
      rate_based_statement {
       limit              = 100
       aggregate_key_type = "IP"
       
       scope_down_statement {
         byte_match_statement {
          field_to_match {
              uri_path   {}
              }
          search_string  = "/media/"
          positional_constraint = "STARTS_WITH"

          text_transformation {
            priority   = 0
            type       = "NONE"
           }
         }
       }
     }
  }
      visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.app["brand"]}-Cloudfront-WAF-Protection-rate-based-rule"
      sampled_requests_enabled   = true
    }
   }
   
   rule {
    name     = "${var.app["brand"]}-Cloudfront-WAF-static-Protection-rate-based"
    priority = 1

    action {
      count {}
    }

    statement {
      rate_based_statement {
       limit              = 200
       aggregate_key_type = "IP"
       
       scope_down_statement {
         byte_match_statement {
          field_to_match {
              uri_path   {}
              }
          search_string  = "/static/"
          positional_constraint = "STARTS_WITH"

          text_transformation {
            priority   = 0
            type       = "NONE"
           }
         }
       }
     }
    }
      visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.app["brand"]}-Cloudfront-WAF-static-Protection-rate-based-rule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name = "AWSManagedRulesCommonRule"
    priority = 2
    override_action {
      none {
      }
    }
    statement {
      managed_rule_group_statement {
        name = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name = "${var.app["brand"]}-AWSManagedRulesCommonRule"
      sampled_requests_enabled = true
    }
  }
  rule {
    name = "AWSManagedRulesAmazonIpReputation"
    priority = 3
    override_action {
      none {
      }
    }
    statement {
      managed_rule_group_statement {
        name = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name = "${var.app["brand"]}-AWSManagedRulesAmazonIpReputation"
      sampled_requests_enabled = true
    }
  }
  rule {
    name = "AWSManagedRulesBotControlRule"
    priority = 4
    override_action {
      none {
      }
    }
    statement {
      managed_rule_group_statement {
        name = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name = "${var.app["brand"]}-AWSManagedRulesBotControlRule"
      sampled_requests_enabled = true
    }
  }
}
