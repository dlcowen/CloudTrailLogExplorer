import boto3
from botocore.exceptions import ClientError
import json
import time

class AWSDiscoveryManager:
    def __init__(self, session):
        self.session = session
        self._current_account_id = None
    
    @property
    def current_account_id(self):
        if not self._current_account_id:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self._current_account_id = identity['Account']
        return self._current_account_id
    
    def discover_accounts(self):
        """Discover AWS accounts accessible to the current credentials"""
        try:
            # Try to use AWS Organizations API first
            org_client = self.session.client('organizations')
            accounts = []
            
            try:
                # List accounts in the organization
                paginator = org_client.get_paginator('list_accounts')
                for page in paginator.paginate():
                    for account in page['Accounts']:
                        if account['Status'] == 'ACTIVE':
                            accounts.append({
                                'AccountId': account['Id'],
                                'Name': account.get('Name', 'Unknown'),
                                'Email': account.get('Email', '')
                            })
                
                print(f"Found {len(accounts)} accounts using Organizations API")
                return accounts
            
            except ClientError as e:
                # Organizations API is not available or not authorized
                print(f"Organizations API error: {str(e)}")
        
        except (ClientError, Exception) as e:
            print(f"Organizations access error: {str(e)}")
        
        # Fallback to just returning the current account
        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            
            return [{
                'AccountId': identity['Account'],
                'Name': 'Current Account',
                'Email': ''
            }]
        
        except Exception as e:
            raise Exception(f"Failed to discover accounts: {str(e)}")
    
    def discover_trails(self, account_id):
        """Discover CloudTrail trails in the specified account"""
        if account_id == self.current_account_id:
            # Use the current session for the current account
            return self._get_trails_for_session(self.session)
        else:
            # Try to assume a role in the target account
            role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
            
            try:
                # Assume the role
                sts = self.session.client('sts')
                response = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="CloudTrailDiscovery"
                )
                
                # Create a session with the assumed role credentials
                session = boto3.Session(
                    aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'],
                    region_name=self.session.region_name
                )
                
                return self._get_trails_for_session(session)
            
            except Exception as e:
                print(f"Error assuming role for account {account_id}: {str(e)}")
                # Return empty list on error
                return []
    
    def _get_trails_for_session(self, session):
        """Get CloudTrail trails using the provided session"""
        try:
            # Query CloudTrail service
            cloudtrail = session.client('cloudtrail')
            response = cloudtrail.describe_trails()
            
            # Process and enrich trail information
            trails = response['trailList']
            
            # Enhance trail information with status and event selectors
            enhanced_trails = []
            for trail in trails:
                try:
                    # Get trail status
                    status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                    
                    # Add relevant status fields
                    trail['IsLogging'] = status.get('IsLogging', False)
                    trail['LatestDeliveryError'] = status.get('LatestDeliveryError', '')
                    trail['LatestDeliveryTime'] = status.get('LatestDeliveryTime', '')
                    trail['LatestDigestDeliveryTime'] = status.get('LatestDigestDeliveryTime', '')
                    
                    # Get event selectors
                    selectors = cloudtrail.get_event_selectors(TrailName=trail['TrailARN'])
                    trail['EventSelectors'] = selectors.get('EventSelectors', [])
                    trail['AdvancedEventSelectors'] = selectors.get('AdvancedEventSelectors', [])
                    
                    enhanced_trails.append(trail)
                except Exception as e:
                    # If we can't get additional details, just add the basic trail info
                    print(f"Error getting details for trail {trail.get('Name')}: {str(e)}")
                    enhanced_trails.append(trail)
            
            return enhanced_trails
        
        except Exception as e:
            print(f"Error discovering trails: {str(e)}")
            return []
    
    def test_cloudtrail_access(self, session):
        """Test if the session has access to CloudTrail"""
        try:
            cloudtrail = session.client('cloudtrail')
            # Try to list trails
            cloudtrail.describe_trails()
            return True
        except Exception as e:
            print(f"CloudTrail access test failed: {str(e)}")
            return False
    
    def test_s3_access_for_cloudtrail(self, session):
        """Test if the session has access to S3 buckets containing CloudTrail logs"""
        try:
            # First get CloudTrail configs to find S3 buckets
            cloudtrail = session.client('cloudtrail')
            s3_client = session.client('s3')
            
            try:
                # Try to list trails to get their S3 buckets
                trails = cloudtrail.describe_trails()
                
                if not trails or not trails.get('trailList'):
                    print("No trails found to test S3 access")
                    return False
                
                # Try to access each CloudTrail bucket
                for trail in trails.get('trailList', []):
                    bucket_name = trail.get('S3BucketName')
                    
                    if not bucket_name:
                        continue
                    
                    try:
                        # Try to list objects in the bucket (max 1)
                        prefix = trail.get('S3KeyPrefix', '')
                        if prefix:
                            prefix = f"{prefix}/AWSLogs/"
                        else:
                            prefix = "AWSLogs/"
                        
                        s3_client.list_objects_v2(
                            Bucket=bucket_name,
                            Prefix=prefix,
                            MaxKeys=1
                        )
                        
                        # If we get here, we have S3 access to at least one bucket
                        return True
                    
                    except Exception as bucket_error:
                        print(f"Cannot access S3 bucket {bucket_name}: {str(bucket_error)}")
                        # Continue to check other buckets
                
                # If we get here, we couldn't access any buckets
                return False
                
            except Exception as trail_error:
                print(f"Error getting trails for S3 test: {str(trail_error)}")
                return False
                
        except Exception as e:
            print(f"S3 access test failed: {str(e)}")
            return False
    
    def get_trail_bucket_info(self, account_id, trail_name):
        """Get detailed information about a trail's S3 bucket"""
        trails = self.discover_trails(account_id)
        
        for trail in trails:
            if trail['Name'] == trail_name:
                bucket_name = trail.get('S3BucketName')
                prefix = trail.get('S3KeyPrefix', '')
                
                return {
                    'bucket_name': bucket_name,
                    'prefix': prefix,
                    'trail_arn': trail.get('TrailARN'),
                    'is_organization_trail': trail.get('IsOrganizationTrail', False),
                    'is_multi_region_trail': trail.get('IsMultiRegionTrail', False)
                }
        
        raise Exception(f"Trail {trail_name} not found in account {account_id}") 