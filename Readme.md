
## Architect Diagram
![Ghost-Application-map](./ghost-infra.drawio.pdf)


## EC2 custom configuration and Auto Scaling management
[User data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html) templates with shell scripts. It uses to send instruction to an instance to perform common automated tasks, application configuration and service settings. 

[**Debian 11** ARM 'bullseye'](https://aws.amazon.com/marketplace/pp/prodview-jwzxq55gno4p4), which will be supported for the next 5 years. Includes support for the very latest ARM-based server systems powered by certified 64-bit processors. Develop and deploy at scale. Webstack delivers top performance on ARM.

[**AWS Systems Manager**](https://aws.amazon.com/systems-manager/) is an AWS service that you can use to view and control your infrastructure on AWS. Using the Systems Manager console, you can view operational data from multiple AWS EC2 instances and automate operational tasks across your AWS resources. Systems Manager helps you maintain security and compliance. No SSH connections from outside, no need to track passwords and private keys.

<br />



# Deployment into isolated VPC:
- [x] Login to AWS Console
- [x] [Subscribe to Debian 11 ARM](https://aws.amazon.com/marketplace/pp/prodview-jwzxq55gno4p4)
- [x] Choose an AWS Region
- [x] Start AWS CloudShell
- [x] Install Terraform:
```
   sudo yum install -y yum-utils
   sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
   sudo yum -y install terraform
```
- [x] Create deployment directory:  
```
  mkdir ghost && cd ghost
```
- [x] Clone repo:  
> 
```
  git clone git@github.com:safoorsafdar/nc-ghost-aws-terraform.git .
```
>  
**[ ! ]** Note: Right after `terraform apply` you will receive email from amazon to approve resources  
**[ ! ]** Check all user_data, adjust your settings, edit your cidr, brand, domain, email and other vars in `variables.tf`  
- [x] Run:
```
   terraform init
   terraform apply
```
> to destroy infrastructure: ```terraform destroy```  
> resources created outside of terraform must be deleted manually, for example CloudWatch logs


# TODO
- Configure the application with Database, CloudFront media and SES in config.production.json. 
at the moment its throwing the error due to sqlite3, it should be picking up with custom define configuration.