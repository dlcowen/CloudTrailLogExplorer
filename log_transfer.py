import boto3
import botocore
import os
import json
import time
import datetime
import logging
import multiprocessing
from threading import Lock
from multiprocessing import Pool
from functools import partial
from botocore.exceptions import ClientError

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('cloudtrail_transfer')

# Standalone function for multiprocessing
def download_log_worker(log_file, bucket_name, destination, session_config=None):
    """Worker function to download a single log file in a separate process"""
    try:
        # Create a new boto3 session in this process if session config is provided
        if session_config:
            session = boto3.Session(
                aws_access_key_id=session_config.get('aws_access_key_id'),
                aws_secret_access_key=session_config.get('aws_secret_access_key'),
                aws_session_token=session_config.get('aws_session_token'),
                region_name=session_config.get('region_name')
            )
            s3 = session.client('s3')
        else:
            # Use default session
            s3 = boto3.client('s3')
        
        key = log_file['key']
        
        # Create subdirectories for the log files to match S3 structure
        if '/' in key:
            # Extract the relative path (after AWSLogs)
            try:
                relative_path = key.split('AWSLogs/')[1]
                target_dir = os.path.join(destination, os.path.dirname(relative_path))
            except:
                # If we can't extract a clean path, use a sanitized version of the key
                sanitized_key = key.replace(':', '_').replace('$', '_')
                target_dir = os.path.join(destination, os.path.dirname(sanitized_key))
        else:
            target_dir = destination
        
        # Ensure target directory exists
        os.makedirs(target_dir, exist_ok=True)
        
        # Construct the target file path
        target_file = os.path.join(target_dir, os.path.basename(key))
        
        # Download the file
        s3.download_file(
            Bucket=bucket_name,
            Key=key,
            Filename=target_file
        )
        
        return {
            'key': key,
            'success': True,
            'error': None,
            'file_size': log_file.get('size', 0)
        }
        
    except Exception as e:
        error_msg = str(e)
        # Log the error
        print(f"Error downloading {log_file.get('key', 'unknown')}: {error_msg}")
        return {
            'key': log_file.get('key', 'unknown'),
            'success': False,
            'error': error_msg,
            'file_size': 0
        }

class LogTransferManager:
    def __init__(self, session):
        self.session = session
        self.transfer_state = None
        self.lock = Lock()
        self.stop_requested = False  # Flag to signal stop
        self.is_running = False
        # Maximum number of concurrent downloads (adjust based on available resources)
        self.max_concurrent_downloads = min(multiprocessing.cpu_count() * 2, 8)
        
        # Error tracking
        self.failed_transfers = []
        self.failed_count = 0
        self.error_log_path = None
        
        # Set up file handler for logging
        self.logger = logger
        
        print("Log Transfer Manager initialized")
    
    def setup_error_logging(self, destination):
        """Set up error logging to a file in the destination directory"""
        try:
            # Create logs directory
            logs_dir = os.path.join(destination, "transfer_logs")
            os.makedirs(logs_dir, exist_ok=True)
            
            # Create log file name with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(logs_dir, f"transfer_errors_{timestamp}.log")
            
            # Set up file handler
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            
            # Add handler to logger
            self.logger.addHandler(file_handler)
            
            # Save log file path
            self.error_log_path = log_file
            
            self.logger.info(f"=== Starting new transfer to {destination} ===")
            return log_file
            
        except Exception as e:
            print(f"Failed to set up error logging: {str(e)}")
            return None
    
    def log_error(self, message, exception=None):
        """Log an error with details"""
        if exception:
            self.logger.error(f"{message}: {str(exception)}")
        else:
            self.logger.error(message)
    
    # Helper method to check if already using the role
    def already_using_role(self, role_arn):
        try:
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            current_arn = identity.get('Arn', '')
            return role_arn in current_arn
        except Exception as e:
            self.logger.warning(f"Could not verify current identity: {str(e)}")
            return False
    
    def start_transfer(self, account_id, trail_name, destination, from_date=None, to_date=None, 
                      progress_callback=None, role_arn=None, auth_info=None):
        """Start transferring logs from a CloudTrail trail to a destination"""
        self.stop_requested = False
        self.is_running = True
        self.failed_transfers = []
        self.failed_count = 0
        log_file = self.setup_error_logging(destination)

        original_auth_info = auth_info or {}

        if role_arn and not self.already_using_role(role_arn):
            try:
                sts_client = self.session.client('sts')
                response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="CloudTrailTransfer"
                )
                role_session = boto3.Session(
                    aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'],
                    region_name=self.session.region_name
                )
                cloudtrail = role_session.client('cloudtrail')
                s3_client = role_session.client('s3')
                active_session = role_session
                self.logger.info(f"Successfully assumed role {role_arn}")
            except Exception as e:
                self.log_error(f"Error assuming role {role_arn}", e)
                cloudtrail = self.session.client('cloudtrail')
                s3_client = self.session.client('s3')
                active_session = self.session
                role_arn = None
        else:
            cloudtrail = self.session.client('cloudtrail')
            s3_client = self.session.client('s3')
            active_session = self.session
            if role_arn:
                self.logger.info(f"Already using role {role_arn}, skipping assumption")

        # Save credentials explicitly for resume
        creds = active_session.get_credentials().get_frozen_credentials()
        saved_creds = {
            'aws_access_key_id': creds.access_key,
            'aws_secret_access_key': creds.secret_key,
            'aws_session_token': creds.token,
            'region_name': active_session.region_name
        }

        # Get trail details to find the S3 bucket
        trail_details = None
        
        try:
            # Try to get trail details
            response = cloudtrail.describe_trails(trailNameList=[trail_name])
            if response['trailList']:
                trail_details = response['trailList'][0]
        except Exception as e:
            print(f"Error getting trail details: {str(e)}")
            self.log_error(f"Error getting trail details for {trail_name}", e)
            raise Exception(f"Failed to get details for trail {trail_name}: {str(e)}")
        
        if not trail_details:
            error_msg = f"Trail {trail_name} not found"
            self.log_error(error_msg)
            raise Exception(error_msg)
        
        # Get S3 bucket info
        bucket_name = trail_details.get('S3BucketName')
        prefix = trail_details.get('S3KeyPrefix', '')
        
        if not bucket_name:
            error_msg = "Trail does not have an S3 bucket configured"
            self.log_error(error_msg)
            raise Exception(error_msg)
        
        # Update progress
        if progress_callback:
            progress_callback(0, 0, f"Scanning CloudTrail logs in bucket {bucket_name}...")
        
        # Build the prefix for CloudTrail logs
        # Format: [prefix]/AWSLogs/[account_id]/CloudTrail/[region]/YYYY/MM/DD/
        if prefix:
            base_prefix = f"{prefix}/AWSLogs/"
        else:
            base_prefix = "AWSLogs/"
            
        # Support for organizational trails
        if trail_details.get('IsOrganizationTrail', False):
            # For org trails, we need to check logs from all accounts
            org_prefix = f"{base_prefix}"
        else:
            # For account-specific trails
            org_prefix = f"{base_prefix}{account_id}/CloudTrail/"
        
        # Find all matching log files
        log_files = []
        
        # Parse date range if provided
        start_date = None
        end_date = None
        
        if from_date:
            try:
                start_date = datetime.datetime.strptime(from_date, "%Y-%m-%d")
            except ValueError:
                error_msg = f"Invalid from_date format: {from_date}. Use YYYY-MM-DD"
                self.log_error(error_msg)
                raise Exception(error_msg)
        
        if to_date:
            try:
                end_date = datetime.datetime.strptime(to_date, "%Y-%m-%d")
                # Set to end of day
                end_date = end_date.replace(hour=23, minute=59, second=59)
            except ValueError:
                error_msg = f"Invalid to_date format: {to_date}. Use YYYY-MM-DD"
                self.log_error(error_msg)
                raise Exception(error_msg)
        
        # If no dates provided, default to last 7 days
        if not start_date:
            end_date = datetime.datetime.now()
            start_date = end_date - datetime.timedelta(days=7)
        
        if not end_date:
            end_date = datetime.datetime.now()
        
        # Update progress
        if progress_callback:
            progress_callback(0, 0, f"Scanning logs from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}...")
        
        # Get all objects matching the date range
        paginator = s3_client.get_paginator('list_objects_v2')
        
        # Keep track of total files scanned
        scanned = 0
        
        for page in paginator.paginate(Bucket=bucket_name, Prefix=org_prefix):
            # Check if stop requested
            if self.stop_requested:
                self.logger.info("Log transfer stopped by user during scanning")
                raise Exception("Log transfer stopped by user")
            
            if 'Contents' in page:
                for obj in page['Contents']:
                    key = obj['Key']
                    
                    # Only process CloudTrail log files
                    if not key.endswith('.json.gz'):
                        continue
                        
                    # Make sure it's actually a CloudTrail log file
                    if '/CloudTrail/' not in key:
                        continue
                    
                    # Extract the date from the object key if possible
                    try:
                        # CloudTrail paths often contain the date in the format:
                        # .../CloudTrail/region/YYYY/MM/DD/...
                        parts = key.split('/')
                        # Find where the region, YYYY, MM, DD parts are
                        for i, part in enumerate(parts):
                            if part == "CloudTrail" and i+4 < len(parts):
                                region = parts[i+1]
                                year = int(parts[i+2])
                                month = int(parts[i+3])
                                day = int(parts[i+4])
                                
                                # Create datetime object
                                file_date = datetime.datetime(year, month, day)
                                
                                # Check if within date range
                                if start_date <= file_date <= end_date:
                                    log_files.append({
                                        'key': key, 
                                        'size': obj['Size'],
                                        'date': file_date,
                                        'last_modified': obj['LastModified']
                                    })
                                break
                    except Exception as date_err:
                        # If we can't parse the date, include the file anyway
                        print(f"Warning: Could not parse date from {key}: {str(date_err)}")
                        self.logger.warning(f"Could not parse date from {key}: {str(date_err)}")
                        log_files.append({
                            'key': key, 
                            'size': obj['Size'],
                            'last_modified': obj['LastModified']
                        })
            
            # Update scanning progress occasionally
            scanned += len(page.get('Contents', []))
            if progress_callback and scanned % 1000 == 0:
                progress_callback(0, 0, f"Scanning logs: {scanned} files examined...")
        
        # Sort log files by date if available
        log_files.sort(key=lambda x: x.get('date', x.get('last_modified', 0)))
        
        # Create destination directory if it doesn't exist
        os.makedirs(destination, exist_ok=True)
        
        # Save the transfer state for potential resume
        self.transfer_state = {
            'account_id': account_id,
            'trail_name': trail_name,
            'bucket_name': bucket_name,
            'destination': destination,
            'from_date': from_date,
            'to_date': to_date,
            'total_logs': len(log_files),
            'transferred_logs': 0,
            'remaining_logs': log_files,
            'completed_logs': [],
            'completed': False,
            'role_arn': role_arn,  # Save the role ARN that was used for this transfer
            'auth_info': original_auth_info,  # Store original auth information
            'failed_count': 0,  # Track failed transfers
            'error_log': log_file,  # Path to error log
            'saved_creds': saved_creds
        }
        
        # Save state to file
        self._save_transfer_state(destination)
        
        # Start the actual download using multiple processes
        self.logger.info(f"Starting transfer of {len(log_files)} files")
        return self._download_logs_async(s3_client, log_files, bucket_name, destination, 
                                        progress_callback, 0, len(log_files), active_session)
    
    def resume_transfer(self, progress_callback=None, auth_manager=None):
        """Resume a previously started transfer"""
        if not self.transfer_state:
            raise Exception("No transfer to resume")
        
        self.stop_requested = False
        self.is_running = True
        
        bucket_name = self.transfer_state.get('bucket_name')
        destination = self.transfer_state.get('destination')
        remaining_logs = self.transfer_state.get('remaining_logs', [])
        saved_creds = self.transfer_state.get('saved_creds')

        if saved_creds:
            active_session = boto3.Session(
                aws_access_key_id=saved_creds['aws_access_key_id'],
                aws_secret_access_key=saved_creds['aws_secret_access_key'],
                aws_session_token=saved_creds['aws_session_token'],
                region_name=saved_creds['region_name']
            )
            s3 = active_session.client('s3')
            self.logger.info("Resumed transfer using saved credentials")
        else:
            active_session = self.session
            s3 = self.session.client('s3')
            self.logger.warning("No saved credentials found, using default session")

        total_logs = self.transfer_state.get('total_logs', len(remaining_logs))
        transferred_logs = self.transfer_state.get('transferred_logs', 0)

        if progress_callback:
            progress_callback(transferred_logs, total_logs, 
                              f"Resuming transfer: {transferred_logs} of {total_logs} already transferred")

        return self._download_logs_async(s3, remaining_logs, bucket_name, destination, 
                                         progress_callback, transferred_logs, total_logs, active_session)
    
    def _download_logs_async(self, s3, log_files, bucket_name, destination, progress_callback=None, 
                           initial_transferred=0, total_logs=None, active_session=None):
        """Download log files from S3 to the destination using a process pool"""
        if total_logs is None:
            total_logs = len(log_files)
        
        transferred = initial_transferred
        completed_logs = []
        batch_failures = 0  # Track failures in current batch
        
        try:
            # Ensure the destination exists
            os.makedirs(destination, exist_ok=True)
            
            # Prepare session config for worker processes
            # Use the active_session if provided (for role-based transfers)
            if active_session and active_session.get_credentials():
                creds = active_session.get_credentials()
                # Check if credentials are expired and need to be refreshed
                if hasattr(creds, 'refresh_needed') and creds.refresh_needed():
                    try:
                        # Force refresh credentials
                        frozen_creds = creds.get_frozen_credentials()
                        print("Refreshed session credentials")
                        self.logger.info("Refreshed session credentials")
                    except Exception as refresh_err:
                        self.logger.warning(f"Failed to refresh credentials: {str(refresh_err)}")
                
                # Get the latest credentials
                frozen_creds = creds.get_frozen_credentials()
                session_config = {
                    'aws_access_key_id': frozen_creds.access_key,
                    'aws_secret_access_key': frozen_creds.secret_key,
                    'aws_session_token': frozen_creds.token,
                    'region_name': active_session.region_name
                }
                
                # Verify credentials are working by testing S3 access to the bucket
                try:
                    test_session = boto3.Session(
                        aws_access_key_id=session_config['aws_access_key_id'],
                        aws_secret_access_key=session_config['aws_secret_access_key'],
                        aws_session_token=session_config['aws_session_token'],
                        region_name=session_config['region_name']
                    )
                    
                    # First check identity
                    test_sts = test_session.client('sts')
                    identity = test_sts.get_caller_identity()
                    self.logger.info(f"Transfer will use credentials for: {identity.get('Arn')}")
                    print(f"Transfer will use credentials for: {identity.get('Arn')}")
                    
                    # Now verify bucket access
                    test_s3 = test_session.client('s3')
                    # Just check if we can list objects (don't actually fetch anything)
                    test_s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                    self.logger.info(f"Successfully verified S3 bucket access for {bucket_name}")
                    print(f"Successfully verified S3 bucket access for {bucket_name}")
                except Exception as access_err:
                    self.logger.warning(f"Pre-transfer S3 access check failed: {str(access_err)}")
                    print(f"Warning: Pre-transfer S3 access check failed: {str(access_err)}")
                    print(f"Some transfers may fail due to permission issues")
                    self.logger.warning("Some transfers may fail due to permission issues")
            elif self.session.get_credentials():
                creds = self.session.get_credentials()
                session_config = {
                    'aws_access_key_id': creds.access_key,
                    'aws_secret_access_key': creds.secret_key,
                    'aws_session_token': creds.token,
                    'region_name': self.session.region_name
                }
            else:
                # Use default credentials
                session_config = {'region_name': self.session.region_name if self.session else 'us-east-1'}
            
            # Create a process pool for downloads
            num_processes = min(len(log_files), self.max_concurrent_downloads)
            if num_processes < 1:
                num_processes = 1
            
            # Update progress
            if progress_callback:
                role_info = ""
                if self.transfer_state and self.transfer_state.get('role_arn'):
                    role_info = f" using role {self.transfer_state.get('role_arn')}"
                
                if self.failed_count > 0:
                    progress_callback(transferred, total_logs, 
                                     f"Starting {num_processes} concurrent downloads{role_info}... ({self.failed_count} failed)")
                else:
                    progress_callback(transferred, total_logs, 
                                     f"Starting {num_processes} concurrent downloads{role_info}...")
            
            # Create partial function with fixed arguments
            download_func = partial(
                download_log_worker,
                bucket_name=bucket_name,
                destination=destination,
                session_config=session_config
            )
            
            # Process in batches to avoid memory issues with large transfers
            batch_size = 100  # Process up to 100 files at a time
            
            for i in range(0, len(log_files), batch_size):
                # Check if stop requested
                if self.stop_requested:
                    # Save state before stopping
                    self.transfer_state['remaining_logs'] = log_files[i:]
                    self.transfer_state['completed_logs'].extend(completed_logs)
                    self.transfer_state['transferred_logs'] = transferred
                    self.transfer_state['failed_count'] = self.failed_count
                    self._save_transfer_state(destination)
                    
                    self.logger.info(f"Transfer stopped by user. {transferred} files transferred, {self.failed_count} failed.")
                    raise Exception("Log transfer stopped by user")
                
                # Get the current batch
                batch = log_files[i:i+batch_size]
                
                # Update progress for new batch
                if progress_callback:
                    if self.failed_count > 0:
                        progress_callback(transferred, total_logs, 
                                         f"Processing batch {i//batch_size + 1} of {(len(log_files)+batch_size-1)//batch_size}... ({self.failed_count} failed)")
                    else:
                        progress_callback(transferred, total_logs, 
                                         f"Processing batch {i//batch_size + 1} of {(len(log_files)+batch_size-1)//batch_size}...")
                
                # Reset batch failure counter
                batch_failures = 0
                
                # Process the batch with a process pool
                with Pool(processes=num_processes) as pool:
                    # Map the download function to the batch of log files
                    results = pool.map(download_func, batch)
                    
                    # Process results
                    for result in results:
                        if self.stop_requested:
                            break
                        
                        key = result.get('key')
                        success = result.get('success', False)
                        error = result.get('error')
                        
                        if success:
                            # Find the original log file data
                            log_file = next((lf for lf in batch if lf['key'] == key), None)
                            if log_file:
                                completed_logs.append(log_file)
                                transferred += 1
                                
                                # Update progress occasionally
                                if transferred % 10 == 0 and progress_callback:
                                    if self.failed_count > 0:
                                        progress_callback(transferred, total_logs, 
                                                        f"Transferred {transferred} of {total_logs} logs ({self.failed_count} failed)")
                                    else:
                                        progress_callback(transferred, total_logs)
                        else:
                            self.failed_count += 1
                            batch_failures += 1
                            # Store the failed transfer
                            self.failed_transfers.append({
                                'key': key,
                                'error': error,
                                'timestamp': datetime.datetime.now().isoformat()
                            })
                            # Log the error
                            self.logger.error(f"Failed to download {key}: {error}")
                            
                            # Update the UI with failure count occasionally
                            if batch_failures % 5 == 0 and progress_callback:
                                progress_callback(transferred, total_logs, 
                                                f"Transferred {transferred}/{total_logs} - {self.failed_count} files failed")
                
                # Update and save state after each batch
                if i + batch_size < len(log_files):
                    self.transfer_state['remaining_logs'] = log_files[i+batch_size:]
                    self.transfer_state['completed_logs'].extend(completed_logs)
                    self.transfer_state['transferred_logs'] = transferred
                    self.transfer_state['failed_count'] = self.failed_count  # Save failed count in state
                    completed_logs = []  # Reset after adding to state
                    self._save_transfer_state(destination)
                    
                    # Also save failed transfers to a separate file for inspection
                    self._save_failed_transfers(destination)
            
            # Mark transfer as complete
            self.transfer_state['completed'] = True
            self.transfer_state['transferred_logs'] = transferred
            self.transfer_state['remaining_logs'] = []
            self.transfer_state['completed_logs'].extend(completed_logs)
            self.transfer_state['failed_count'] = self.failed_count
            self._save_transfer_state(destination)
            
            # Save final failed transfers report
            self._save_failed_transfers(destination)
            
            self.is_running = False
            
            # Log completion
            self.logger.info(f"Transfer complete. {transferred} files transferred successfully, {self.failed_count} files failed.")
            if self.failed_count > 0:
                self.logger.info(f"See detailed error log at: {self.error_log_path}")
                self.logger.info(f"Failed transfers summary: {destination}/failed_transfers.json")
            
            return total_logs, transferred, self.failed_count
        
        except Exception as e:
            self.log_error("Download process failed", e)
            
            if not self.stop_requested:
                # Only save state on error if not explicitly stopped
                remaining_index = next((i for i, log in enumerate(log_files) 
                                      if log['key'] not in [c['key'] for c in completed_logs]), 0)
                self.transfer_state['remaining_logs'] = log_files[remaining_index:]
                self.transfer_state['completed_logs'].extend(completed_logs)
                self.transfer_state['transferred_logs'] = transferred
                self.transfer_state['failed_count'] = self.failed_count
                self._save_transfer_state(destination)
                
                # Save failed transfers
                self._save_failed_transfers(destination)
            
            self.is_running = False
            raise e
    
    def _save_failed_transfers(self, destination):
        """Save a report of failed transfers to a JSON file"""
        if not self.failed_transfers:
            return
        
        try:
            failures_file = os.path.join(destination, "failed_transfers.json")
            with open(failures_file, 'w') as f:
                json.dump({
                    'failed_count': self.failed_count,
                    'failures': self.failed_transfers,
                    'error_log': self.error_log_path
                }, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save failed transfers report: {str(e)}")
    
    def _save_transfer_state(self, destination):
        """Save the current transfer state to a file in the destination directory"""
        if not self.transfer_state:
            return
        
        state_file = os.path.join(destination, ".transfer_state.json")
        
        try:
            with open(state_file, 'w') as f:
                # Convert datetime objects to strings for JSON serialization
                state_copy = dict(self.transfer_state)
                
                # Process remaining_logs
                for log in state_copy.get('remaining_logs', []):
                    if 'date' in log and isinstance(log['date'], datetime.datetime):
                        log['date'] = log['date'].isoformat()
                    if 'last_modified' in log and hasattr(log['last_modified'], 'isoformat'):
                        log['last_modified'] = log['last_modified'].isoformat()
                
                # Process completed_logs
                for log in state_copy.get('completed_logs', []):
                    if 'date' in log and isinstance(log['date'], datetime.datetime):
                        log['date'] = log['date'].isoformat()
                    if 'last_modified' in log and hasattr(log['last_modified'], 'isoformat'):
                        log['last_modified'] = log['last_modified'].isoformat()
                
                json.dump(state_copy, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save transfer state: {str(e)}")
            self.log_error("Failed to save transfer state", e)
    
    def stop_transfer(self):
        """Request to stop the current transfer"""
        self.logger.info("Stop transfer requested by user")
        self.stop_requested = True
    
    def can_resume(self):
        """Check if there's a transfer that can be resumed"""
        return (self.transfer_state is not None and 
                not self.transfer_state.get('completed', False) and
                self.transfer_state.get('remaining_logs', []))
    
    def get_failure_summary(self):
        """Get a summary of failed transfers"""
        if not self.failed_transfers:
            return None
        
        return {
            'count': self.failed_count,
            'log_path': self.error_log_path
        } 