'''
Lambda function to iterate ELB listeners each account has, and determine if a SSL certificate is going to expire. 
If the certificate already expired or is about to, send an email to the emailContact tag listed in the ELB.

Note: Account ID's, role names, and other sensitive data has been hidden for publication manners.
'''

import boto3
from botocore.exceptions import ClientError
from datetime import date, datetime, timedelta
import datetime

def createMail(email, certificate, balancerName, msg):
    SENDER = "Automation Team <mail@domain.com>"
    
    RECIPIENT = email
    
    SUBJECT = "Amazon SSL Certificate Expiration Reminder"
    
    BODY_TEXT = ("Amazon SSL Certificate Expiration Reminder\r\n"
    "Hello "+email+"\r\n"
    "The certificate "+certificate+" attached to your ELB "+balancerName+"\r\n"+
    msg+"\r\n"
    "Please make the necessary changes to stop receiveing these emails."
    )
    
    BODY_HTML = """
        <html>
        <head></head>
        <body>
            <h1>Amazon Certificate Expiration Reminder</h1>
            
            <p>Hello <b>"""+email+"""</b></p>
            <p>The certificate <b>'"""+certificate+"""'</b> attached to your ELB <b>'"""+balancerName+"""'</b></p>
            <p>"""+msg+"""</b></p>
            <p>Please make the necessary changes to stop receiveing these emails.</p>
        </body>
        </html>
    """
    
    CHARSET = "UTF-8"
    
    client = boto3.client('ses')
    
    # Try to send the email.
    try:
        #Provide the contents of the email.
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    RECIPIENT,
                ],
            },
            
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML,
                    },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': BODY_TEXT,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            
            Source=SENDER
        )
        
    # Display an error if something goes wrong.	
    except ClientError as e:
        return("Error! Message: "+e.response['Error']['Message'])
    else:
        return("Email sent! Message ID: "+response['MessageId'])
        
def generateMessage(expirationDateTimeStamp):
    #Check if the certificate will expire
    today = date.today()
    #Convert datetime to date
    expDay = expirationDateTimeStamp.date()
    
    msg = ""
    
    #Conditions to send email
    if today <= expDay:
        #Message for expiration in 21, 14 or 7 days
        if expDay == (today + timedelta(days=21)) or expDay == (today + timedelta(days=14)) or expDay == (today + timedelta(days=7)):
            msg = "Will expire in "+str((expDay-today).days)+" days"
        
        #Message for expiration in 1 day
        elif expDay == (today + timedelta(days=1)):
            msg = "Will expire in "+str((expDay-today).days)+" day"
            
        #Message for expiration in 0 days
        elif expDay == today:
            msg = "Expires today"
    
    else:
        #Message every 7 days after exp date
        if ((((today-expDay).days) % 7) == 0):
            msg = "Expired "+str((today-expDay).days)+" days ago"
            
    return (msg)
    
def getExpirationDate(certificate, serverCertificatesIAM, acm):
    expirationDateTimeStamp = ""
    
    #Check IAM certificates
    if ":iam:" in certificate:
        for certificateIAM in serverCertificatesIAM:
            if certificateIAM["Arn"] == certificate:
                expirationDateTimeStamp = certificateIAM["Expiration"]
    #Check ACM certificates
    elif ":acm:" in certificate:
        serverCertificatesACM = acm.describe_certificate(CertificateArn = certificate)['Certificate']
        expirationDateTimeStamp = serverCertificatesACM['NotAfter']
        
    return(expirationDateTimeStamp)

def lambda_handler(event, context):
    sts_client = boto3.client('sts')
    
    #Assume role into a different account
    assumed_role_object_for_accounts=sts_client.assume_role(
        RoleArn="arn:aws:iam::account:role/roleName",
        RoleSessionName="AssumeRoleListAccounts"
    )
    
    credentials_for_accounts = assumed_role_object_for_accounts['Credentials']
    
    # Use the temporary credentials that AssumeRole returns to make a 
    # connection to Amazon Organizations service and get the accounts
    organizations = boto3.client(
        'organizations',
        aws_access_key_id=credentials_for_accounts['AccessKeyId'],
        aws_secret_access_key=credentials_for_accounts['SecretAccessKey'],
        aws_session_token=credentials_for_accounts['SessionToken'] 
    )
    
    #Get the accounts using the boto3 API
    response_accounts = organizations.list_accounts()
    accountList = response_accounts['Accounts']
    while "NextToken" in response_accounts:
        response_accounts = organizations.list_accounts(NextToken=response_accounts['NextToken'])
        accountList.extend(response_accounts['Accounts'])
    
    sts_client_2 = boto3.client('sts')
    
    msg_response = []
    mails = []
    
    #Iterate in each of the accounts
    for account in accountList:
        try:
            # Call the assume_role method of the STSConnection object and pass the role
            assumed_role_object = sts_client_2.assume_role(
                RoleArn="arn:aws:iam::"+account['Id']+":role/roleName",
                RoleSessionName="AssumeRoleCheckCertificates"
            )
        
            credentials = assumed_role_object['Credentials']
        except ClientError as e:
            #If it can't assume role, move to the next account
            continue
        
        # Use the temporary credentials that AssumeRole returns to make a 
        # connection to Amazon ELB, IAM and ACM
        #Get the load balancer from each account
        elb = boto3.client(
            'elb',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
            
        elbv2 = boto3.client(
            'elbv2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        load_balancers_elb = []
        load_balancers_elbv2 = []
        
        #Get all the load balancers
        response_elb = elb.describe_load_balancers()
        load_balancers_elb.extend(response_elb['LoadBalancerDescriptions'])
        while "NextMarker" in response_elb:
            response_elb = elb.describe_load_balancers(NextMarker=response_elb['NextMarker'])
            load_balancers_elb.extend(response_elb['LoadBalancerDescriptions'])
                
        response_elbv2 = elbv2.describe_load_balancers()
        load_balancers_elbv2.extend(response_elbv2['LoadBalancers'])
        while "NextMarker" in response_elbv2:
            response_elb = elbv2.describe_load_balancers(NextMarker=response_elbv2['NextMarker'])
            load_balancers_elbv2.extend(response_elbv2['LoadBalancers'])
        
        #Access the IAM and ACM resources
        iam = boto3.client(
            'iam',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        acm = boto3.client(
            'acm',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        #Get IAM certificates, if it fails, move to next account
        try:
            response_iam = iam.list_server_certificates()
        except ClientError as e:
            continue
        
        serverCertificatesIAM = response_iam['ServerCertificateMetadataList']
        while "Marker" in response_iam:
            response_iam = iam.list_server_certificates(Marker=response_iam['Marker'])
            serverCertificatesIAM.extend(response_iam['ServerCertificateMetadataList'])

        #Process data from each load balancers from the v1 api
        for balancer in load_balancers_elb:
            balancerName = balancer['LoadBalancerName']
            
            for elb_listener in balancer['ListenerDescriptions']:
                #Condition to verify the listener has a SSL Certificate
                if "SSLCertificateId" in elb_listener['Listener']:
                    #Check if the SSL Cert will expire
                    certificate = elb_listener['Listener']['SSLCertificateId']
                    
                    #Retrieve expiration date from the certificate
                    expirationDateTimeStamp = getExpirationDate(certificate, serverCertificatesIAM, acm)
                        
                    if expirationDateTimeStamp:
                        msg = generateMessage(expirationDateTimeStamp)
                                
                        #Get the email tag
                        tagDesc = elb.describe_tags(
                            LoadBalancerNames=[
                                balancerName
                            ]
                        )['TagDescriptions']
                        
                        email = ""
                        
                        for tags in tagDesc[0]['Tags']:
                            if tags["Key"] == "EmailContact":
                                email = (tags["Value"])
                        
                        #Condition to check if the msg was created and there was an email
                        if email and msg:
                            mails.append((email,certificate, balancerName,msg))
                            
        #Process data from each load balancers from the v2 api
        for balancer in load_balancers_elbv2:
            balancerName = balancer['LoadBalancerName']
            balancerArn = balancer['LoadBalancerArn']
            
            #Get the listeners from the lb
            response_listeners = elbv2.describe_listeners(LoadBalancerArn = balancerArn)
            elbv2_listeners = response_listeners['Listeners']
            while "NextMarker" in response_listeners:
                response_listeners = elbv2.describe_listeners(NextMarker=response_listeners['NextMarker'])
                elbv2_listeners.extend(response_listeners['Listeners'])
            
            for elbv2_listener in elbv2_listeners:
                listener = elbv2_listener['ListenerArn']
                for certificates in elbv2_listener.get('Certificates', []):
                    certificate = certificates['CertificateArn']
                    
                    #Retrieve expiration date from the certificate
                    expirationDateTimeStamp = getExpirationDate(certificate, serverCertificatesIAM, acm)
                        
                    if expirationDateTimeStamp:
                        #Create the message to be sent
                        msg = generateMessage(expirationDateTimeStamp)
                        
                        #Get the email tag
                        tagDesc = elbv2.describe_tags(
                            ResourceArns=[
                                balancerArn
                            ]
                        )['TagDescriptions']
                        
                        email = ""
                        
                        for tags in tagDesc[0]['Tags']:
                            if tags["Key"] == "EmailContact":
                                email = (tags["Value"])
                        
                        #Condition to check if the msg was created and there was an email
                        if email and msg:
                            mails.append((email,certificate, balancerName,msg))
    
    #Create and send mails
    for mail in mails:
        msg_response.append(createMail(mail[0], mail[1], mail[2], mail[3]))
    
    return msg_response
