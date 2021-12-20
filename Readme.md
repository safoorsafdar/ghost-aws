# Ghost Auto Scaling Infrastructure with Terraform on AWS Cloud

>Deploy a full-scale secure and flexible cms infrastructure based on Ghost in a matter of seconds.

<br />

The terraform configuration language and all the files in this repository are intuitively simple and straightforward. Terraform deployment with zero dependency, no prerequisites, no need to install additional software, no programming required.  
  
The idea is to create a full-fledge turnkey infrastructure, with deeper settings, so that any one can deploy it and immediately use it.

<br />

## EC2 webstack custom configuration and Auto Scaling management

[User data][userdata] templates with shell scripts. If you are familiar with shell scripting, this is the easiest and most complete way to send instructions to an instance to perform common automated configuration tasks and even run scripts after the instance starts. From default stack optimization to changing any application and service settings.

[**Warm pools** for Amazon EC2 Auto Scaling][asg] - A warm pool gives you the ability to decrease latency for your applications. With warm pools, you no longer have to over-provision your Auto Scaling groups to manage latency in order to improve application performance. You have the option of keeping instances in the warm pool in one of two states: `Stopped` or `Running`. Keeping instances in a `Stopped` state is an effective way to minimize costs.

NGINX is optimized and fully supported on the latest generation of 64-bit ARM Servers utilizing the architecture.

Configuration for this has been set to 1 as it come to my intention bit later that Ghost is not set to have cluster instances.

[**Debian 11** ARM 'bullseye'][Debian-11-ARM], which will be supported for the next 5 years. Includes support for the very latest ARM-based server systems powered by certified 64-bit processors.
Develop and deploy at scale. Webstack delivers top performance on ARM.

[**AWS Systems Manager**][ssm] is an AWS service that you can use to view and control your infrastructure on AWS. Using the Systems Manager console, you can view operational data from multiple AWS EC2 instances and automate operational tasks across your AWS resources. Systems Manager helps you maintain security and compliance. No SSH connections from outside, no need to track passwords and private keys.

## Developer documentation to read

```text
https://ghost.org/
https://docs.aws.amazon.com/index.html
https://www.terraform.io/docs/
https://aws.amazon.com/cloudshell/
```

<br />


## :rocket: Deployment into isolated VPC

- [x] Login to AWS Console
- [x] [Subscribe to Debian 11 ARM][Debian-11-ARM]
- [x] Choose an AWS Region
- [x] Start AWS CloudShell
- [x] Install Terraform:

```sh
   sudo yum install -y yum-utils
   sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
   sudo yum -y install terraform
```

- [x] Create deployment directory:  

```sh
  mkdir ghost && cd ghost
```

- [x] Clone repo:  

>

```sh
  git clone git@github.com:safoorsafdar/nc-ghost-aws-terraform.git .
```

>  
**[ ! ]** Note: Right after `terraform apply` you will receive email from amazon to approve resources  
**[ ! ]** Check all user_data, adjust your settings, edit your cidr, brand, domain, email and other vars in `variables.tf`  

- [x] Run:

```sh
   terraform init
   terraform apply
```

> to destroy infrastructure: ```terraform destroy```  
> resources created outside of terraform must be deleted manually, for example CloudWatch logs
> `aws-nuke` basic configuration is also present under `aws-nuke` directory which can also be used to destruct the resources from aws account.

## Complete setup look like this

- autoscaling groups with launch templates converted from `user_data`  
- target groups for load balancer (frontend)
- load balancers (external) with listeners / rules  
- rds mariadb databases multi AZ production, single AZ staging  
- s3 buckets for [media] images and [system] files and logs (with access policy)  
- codecommit app files repository and services config files repository  
- cloudfront s3 origin distribution  
- sns topic default subscription to receive email alerts  
- ses user access details for smtp module  

 >resources are grouped into a virtual network, VPC dedicated to your brand  
 >the settings initially imply a large app and are designed for huge traffic.  
 >services are clustered and replicated thus ready for failover.

### Deployment detail

- [x] Deployment into isolated Virtual Private Cloud
- [x] Autoscaling policy per each group
- [x] Managed with [Systems Manager][ssm] agent
- [x] Instance Profile assigned to simplify EC2 management
- [x] Create and use ssm documents, and SSM doc to install basic ghost
- [x] Simple Email Service authentication + SMTP module for ghost is pending
- [x] CloudWatch agent configured to stream logs, configuration files is store on SSM Parameter Store
- [x] All ghost files managed with git only
- [x] Configuration settings saved in Parameter Store
- [x] Live CMS in production mode / read-only
- [x] Security groups configured for every service and instances
- [x] Enhanced security in AWS and Nginx with NodeJS.
- [x] AWS Inspector Assessment templates
- [x] AWS WAF Protection rules for media access only.  

## :hammer_and_wrench: Ghost development | source code

- [x] Local provisioner copy files from [Ghost Source Code][ghost-source-code]
- [x] Pickup files from your own repo @ [variables.tf#L20](https://github.com/safoorsafdar/nc-ghost-aws-terraform/blob/main/variables.tf#L10)
- [x] Files saved to AWS CloudShell /tmp directory and pushed to CodeCommit.
- [x] Later on EC2 instance user_data configured on boot to clone files from CodeCommit branch.
- [x] Right after infrastructure deployment the minimal Ghost package is ready to install.
- [x] Check and run SSM Document to install Ghost

> Source code directly downloaded from Ghost official Github repo without adding the any custom module in it such as cloudfront with s3 media bucket.


## CI/CD Scenario

CI/CD is not present in the current implementation, but we can use below mentioned approach:

- Event driven
- Services configuration files tracked in CodeCommit repository
- Changes in CodeCommit repository triggers EventBridge rule.
- SSM Document pull from CodeCommit repository and cleanup.
- Deployment logic based on in-place change strategy.  
- or maybe prepare golden images pipeline to have blue-green deployment.

<br />

[Debian-11-ARM]: https://aws.amazon.com/marketplace/pp/prodview-jwzxq55gno4p4
[ssm]: https://aws.amazon.com/systems-manager/
[asg]: https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-warm-pools.html
[userdata]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html
[ghost-source-code]: https://github.com/safoorsafdar/Ghost