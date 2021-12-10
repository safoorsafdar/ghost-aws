## Taken from https://diagrams.mingrammer.com/

# diagram.py
from diagrams import Diagram
from diagrams.aws.compute import EC2Instance
from diagrams.aws.database import RDS
from diagrams.aws.network import ELB
from diagrams.aws.network import CloudFront
from diagrams.aws.storage import SimpleStorageServiceS3BucketWithObjects
from diagrams.aws.enablement import ManagedServices
from diagrams.aws.engagement import SimpleEmailServiceSes
from diagrams.aws.management import Cloudwatch
from diagrams.aws.integration import SimpleNotificationServiceSns
from diagrams.aws.database import RDSMysqlInstance
from diagrams.aws.security import WAF
from diagrams.aws.compute import EC2Ami
from diagrams.aws.compute import EC2AutoScaling
from diagrams.aws.security import CertificateManager
from diagrams.aws.devtools import Codecommit
from diagrams.aws.general import Users
from diagrams.aws.network import Route53

from diagrams.aws.cost import Budgets


from diagrams.onprem.client import Client, Users
from diagrams.onprem.network import Internet

with Diagram("Ghost", show=False):
    route = Route53("Route53")
    users = Users()
    alb = ELB("Application Load Balancer")
    cloudFront = CloudFront("Cloud Front")
    s3Media = SimpleStorageServiceS3BucketWithObjects("media")
    s3System = SimpleStorageServiceS3BucketWithObjects("system")
    s3Backup = SimpleStorageServiceS3BucketWithObjects("backup")
    ssm = ManagedServices("SSM")
    ses = SimpleEmailServiceSes("SES")
    sns = SimpleNotificationServiceSns("SNS")
    rds = RDSMysqlInstance("MysqlRDS")
    waf = WAF("WAF")
    ec2ami = EC2Ami("Debain11")
    ssl = CertificateManager("SSl")
    appCode =  Codecommit("app code")
    servicesCode = Codecommit("services code")
    
    budget = Budgets("budget-monthly-forecasted")

    with Cluster("AWS"):
        with Cluster("CDN"):
            cdn = S3("S3") >> CF("CloudFront CDN")
        with Cluster("Frontend"):
           frontend = EC2AutoScaling("frontend") <<  [EC2Instance("C6G"), EC2Instance("C6G"), EC2Instance("C6G"), EC2Instance("C6G"), EC2Instance("C6G")]
    
    #application logging 
    # cloud front logs to s3 systes
    # alb logs to s3 system
    # frontend server logs 
    ## /var/log/nginx/error.log
    ## /var/log/syslog
    ## /var/log/apt/history.log
    ## /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log
    ## /var/www/nghost/content/logs/nghost.error.log
    ## /var/www/nghost/content/logs/nghost.log

    # Monitoring - RDS 
    ## Cloudwatch - Alert: rds cpu utilization too high
    ## Cloudwatch - Alert: rds freeable memory too low
    ## Cloudwatch - Alert: rds connections anomaly
    ## Cloudwatch - Alert: rds connections over last 10 minutes is too high
    # Monitoring - ALB
    ## Cloudwatch - Alert: http-5xx-errors-from-target
    ## Cloudwatch - Alert: http-5xx-errors-from-loadbalancer
    ## Cloudwatch - Alert: loadbalancer-rps
    # Monitoring - ASG
    ## Cloudwatch - Alert: scale-out alarm
    ## Cloudwatch - Alert: scale-in alarm
    



    alb >> frontend

     Client() -
        Internet("www.yoursite.com") >> 
        Edge(color="darkgreen", style="dotted") << 
        route >> Edge() << alb