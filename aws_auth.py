import boto3
import botocore
import os
import configparser
import json
from botocore.exceptions import ClientError

class AWSAuthManager:
    def __init__(self):
        self.session = None
        self.credentials = None
        self.account_id = None
        self.region = None
    
    def get_available_profiles(self):
        """Get a list of available AWS profiles from ~/.aws/credentials"""
        profiles = []
        
        # Check for credentials file
        credentials_path = os.path.expanduser("~/.aws/credentials")
        if os.path.exists(credentials_path):
            config = configparser.ConfigParser()
            config.read(credentials_path)
            profiles = config.sections()
        
        # Check for config file
        config_path = os.path.expanduser("~/.aws/config")
        if os.path.exists(config_path):
            config = configparser.ConfigParser()
            config.read(config_path)
            for section in config.sections():
                if section.startswith("profile "):
                    profile_name = section[8:]  # Remove "profile " prefix
                    if profile_name not in profiles:
                        profiles.append(profile_name)
        
        return profiles
    
    def get_available_regions(self):
        """Get a list of available AWS regions"""
        # This is a static list of common regions
        regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "ca-central-1",
            "eu-west-1", "eu-west-2", "eu-west-3",
            "eu-central-1", "eu-north-1",
            "ap-east-1", "ap-south-1",
            "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
            "ap-southeast-1", "ap-southeast-2",
            "sa-east-1",
            "us-gov-east-1", "us-gov-west-1"
        ]
        return regions
    
    def authenticate_with_profile(self, profile_name, region):
        """Authenticate with AWS using a profile"""
        try:
            self.session = boto3.Session(profile_name=profile_name, region_name=region)
            self.credentials = self.session.get_credentials()
            self.region = region
            
            # Get the account ID
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            
            return True
        except Exception as e:
            raise Exception(f"Failed to authenticate with profile {profile_name}: {str(e)}")
    
    def authenticate_with_keys(self, access_key, secret_key, region):
        """Authenticate with AWS using access and secret keys"""
        try:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            self.credentials = self.session.get_credentials()
            self.region = region
            
            # Get the account ID
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            
            return True
        except Exception as e:
            raise Exception(f"Failed to authenticate with access keys: {str(e)}")

    def discover_available_roles(self):
        """Discover IAM roles that can be assumed by the current credentials"""
        if not self.session:
            raise Exception("Not authenticated with AWS")
        
        available_roles = []
        
        try:
            # First, get the current identity to determine user/role ARN
            sts_client = self.session.client('sts')
            current_identity = sts_client.get_caller_identity()
            current_arn = current_identity['Arn']
            
            # Try to list roles using IAM
            iam_client = self.session.client('iam')
            
            # List roles and check if they can be assumed
            paginator = iam_client.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_arn = role['Arn']
                    
                    # Skip service-linked roles which can't be manually assumed
                    if "/aws-service-role/" in role_arn:
                        continue
                    
                    # Try to determine if the role can be assumed by the current identity
                    # by checking the trust policy
                    try:
                        can_assume = False
                        
                        # Get the role's trust policy
                        assume_role_policy = role['AssumeRolePolicyDocument']
                        
                        # Check if the current identity can assume this role
                        for statement in assume_role_policy.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                principal = statement.get('Principal', {})
                                
                                # Check AWS service principals
                                if 'Service' in principal:
                                    continue  # Skip service principals
                                
                                # Check AWS account principals
                                if 'AWS' in principal:
                                    aws_principals = principal['AWS']
                                    if not isinstance(aws_principals, list):
                                        aws_principals = [aws_principals]
                                    
                                    for aws_principal in aws_principals:
                                        # Check if the current identity's ARN or account is allowed
                                        if (aws_principal == '*' or 
                                            aws_principal == current_arn or 
                                            aws_principal == f"arn:aws:iam::{current_identity['Account']}:root"):
                                            can_assume = True
                                            break
                                
                                # Check if role allows the current role/user to assume it
                                if 'AWS' in principal:
                                    # Already checked above
                                    pass
                        
                        if can_assume:
                            available_roles.append(role_arn)
                    
                    except Exception as e:
                        # Skip roles we can't parse or access
                        print(f"Error checking trust policy for role {role_arn}: {str(e)}")
            
            # If we couldn't find roles through IAM analysis, try a different approach
            # using organizations API if available
            if not available_roles:
                try:
                    org_client = self.session.client('organizations')
                    
                    # Get all accounts in the organization
                    accounts = []
                    paginator = org_client.get_paginator('list_accounts')
                    
                    for page in paginator.paginate():
                        accounts.extend(page['Accounts'])
                    
                    # Add standard cross-account admin roles that might exist
                    for account in accounts:
                        account_id = account['Id']
                        if account_id != current_identity['Account']:  # Skip current account
                            # Add common cross-account roles
                            for role_name in ["OrganizationAccountAccessRole", "AdminRole", "AdministratorAccess"]:
                                role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                                available_roles.append(role_arn)
                
                except Exception as org_error:
                    # Organizations API might not be available or accessible
                    print(f"Could not use Organizations API: {str(org_error)}")
            
            # Add roles in the current account that might be assumable
            try:
                response = iam_client.list_roles()
                for role in response['Roles']:
                    role_arn = role['Arn']
                    if role_arn not in available_roles and "/aws-service-role/" not in role_arn:
                        available_roles.append(role_arn)
            except Exception as e:
                print(f"Error listing roles in current account: {str(e)}")
                
            return available_roles
        
        except Exception as e:
            raise Exception(f"Failed to discover available roles: {str(e)}")
    
    def assume_role(self, role_arn, session_name=None):
        """Assume an IAM role and return a session with that role's credentials"""
        if not self.session:
            raise Exception("Not authenticated with AWS")
        
        if not session_name:
            session_name = "CloudTrailExplorer"
        
        try:
            sts_client = self.session.client('sts')
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600  # 1 hour session
            )
            
            # Create a new session with the assumed role credentials
            role_session = boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken'],
                region_name=self.region
            )
            
            return role_session
        
        except Exception as e:
            raise Exception(f"Failed to assume role {role_arn}: {str(e)}") 