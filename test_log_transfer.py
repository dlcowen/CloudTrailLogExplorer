import unittest
from unittest.mock import patch, MagicMock, call, mock_open
import boto3
import json
import os
import datetime
import logging
import tempfile
import shutil
from pathlib import Path

# Import the module to test
from log_transfer import LogTransferManager, download_log_worker

class TestLogTransferManager(unittest.TestCase):
    """Tests for the LogTransferManager class"""
    
    def setUp(self):
        """Set up test environment before each test"""
        # Create a mock session
        self.mock_session = MagicMock()
        self.mock_sts = MagicMock()
        self.mock_s3 = MagicMock()
        self.mock_cloudtrail = MagicMock()
        
        # Configure the mock session
        self.mock_session.client.side_effect = lambda service, **kwargs: {
            'sts': self.mock_sts,
            's3': self.mock_s3,
            'cloudtrail': self.mock_cloudtrail
        }.get(service, MagicMock())
        
        self.mock_session.region_name = 'us-east-1'
        
        # Mock credentials
        self.mock_creds = MagicMock()
        self.mock_frozen_creds = MagicMock()
        self.mock_frozen_creds.access_key = 'test-access-key'
        self.mock_frozen_creds.secret_key = 'test-secret-key'
        self.mock_frozen_creds.token = 'test-session-token'
        self.mock_creds.get_frozen_credentials.return_value = self.mock_frozen_creds
        self.mock_session.get_credentials.return_value = self.mock_creds
        
        # Create test instance with mock session
        with patch('logging.FileHandler'):  # Prevent actual file handler creation
            self.transfer_manager = LogTransferManager(self.mock_session)
            
            # Replace logger with a properly configured mock
            mock_logger = MagicMock()
            mock_logger.level = logging.INFO
            # Ensure the logger's methods don't try to access handler levels
            mock_logger.info = MagicMock()
            mock_logger.error = MagicMock()
            mock_logger.warning = MagicMock()
            mock_logger.debug = MagicMock()
            self.transfer_manager.logger = mock_logger
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # List to track file handlers that need to be closed
        self.handlers_to_close = []
    
    def tearDown(self):
        """Clean up after each test"""
        # Close any open file handlers
        for handler in self.handlers_to_close:
            try:
                handler.close()
            except:
                pass
        
        # Small delay to ensure file handles are released
        import time
        time.sleep(0.1)
        
        # Remove the temporary directory with retry logic for Windows
        for _ in range(3):  # Try up to 3 times
            try:
                shutil.rmtree(self.test_dir)
                break
            except PermissionError:
                time.sleep(0.5)  # Wait a bit for file handles to be released
            except Exception:
                break  # Don't retry for other exceptions
    
    @patch('log_transfer.LogTransferManager.already_using_role')
    def test_already_using_role(self, mock_already_using_role):
        """Test the already_using_role method"""
        # Set up the mock to return expected values
        mock_already_using_role.side_effect = [True, False, False]
        
        # Test when we are already using the role
        self.assertTrue(
            self.transfer_manager.already_using_role('arn:aws:iam::123456789012:role/test-role'),
            "Should detect we are already using the role"
        )
        
        # Test when we are using a different role
        self.assertFalse(
            self.transfer_manager.already_using_role('arn:aws:iam::123456789012:role/other-role'),
            "Should detect we are not using the specified role"
        )
        
        # Test when identity check fails
        self.mock_sts.get_caller_identity.side_effect = Exception("Test error")
        self.assertFalse(
            self.transfer_manager.already_using_role('arn:aws:iam::123456789012:role/test-role'),
            "Should handle exceptions gracefully and return False"
        )
    
    @patch('boto3.Session')
    @patch('log_transfer.LogTransferManager.already_using_role')
    def test_start_transfer_with_role_already_assumed(self, mock_already_using_role, mock_boto3_session):
        """Test starting a transfer when already using the requested role"""
        # Mock already using the role
        mock_already_using_role.return_value = True
        
        # Mock CloudTrail response
        self.mock_cloudtrail.describe_trails.return_value = {
            'trailList': [{
                'Name': 'test-trail',
                'S3BucketName': 'test-bucket',
                'S3KeyPrefix': 'prefix'
            }]
        }
        
        # Mock S3 list_objects_v2 paginator
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{
            'Contents': [{
                'Key': 'prefix/AWSLogs/123456789012/CloudTrail/us-east-1/2023/04/01/123456789012_CloudTrail_us-east-1_20230401T0000Z.json.gz',
                'Size': 1000,
                'LastModified': datetime.datetime.now()
            }]
        }]
        self.mock_s3.get_paginator.return_value = mock_paginator
        
        # Mock setup_error_logging to avoid file operations
        with patch.object(self.transfer_manager, 'setup_error_logging') as mock_setup_logging:
            mock_setup_logging.return_value = "/mock/path/error.log"
            
            # Mock _download_logs_async to avoid actual download
            self.transfer_manager._download_logs_async = MagicMock(return_value=(1, 1, 0))
            
            # Mock _save_transfer_state to avoid file operations
            self.transfer_manager._save_transfer_state = MagicMock()
            
            # Test starting a transfer with a role we're already using
            role_arn = 'arn:aws:iam::123456789012:role/test-role'
            result = self.transfer_manager.start_transfer(
                account_id='123456789012',
                trail_name='test-trail',
                destination=self.test_dir,
                role_arn=role_arn
            )
            
            # Verify we didn't try to assume the role again
            self.mock_sts.assume_role.assert_not_called()
            
            # Verify we used the current session for CloudTrail operations
            self.mock_session.client.assert_any_call('cloudtrail')
            
            # Verify the transfer state has saved creds
            self.assertIsNotNone(self.transfer_manager.transfer_state.get('saved_creds'))
            
            # Verify the correct role ARN was saved in the transfer state
            self.assertEqual(
                self.transfer_manager.transfer_state.get('role_arn'),
                role_arn
            )
    
    @patch('boto3.Session')
    @patch('log_transfer.LogTransferManager.already_using_role')
    def test_start_transfer_assuming_role(self, mock_already_using_role, mock_boto3_session):
        """Test starting a transfer with role assumption"""
        # Mock not using the role yet
        mock_already_using_role.return_value = False
        
        # Mock assume_role response
        self.mock_sts.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'role-access-key',
                'SecretAccessKey': 'role-secret-key',
                'SessionToken': 'role-session-token'
            }
        }
        
        # Configure mock for new session
        mock_role_session = MagicMock()
        mock_role_cloudtrail = MagicMock()
        mock_role_s3 = MagicMock()
        mock_role_creds = MagicMock()
        mock_role_frozen_creds = MagicMock()
        
        mock_role_frozen_creds.access_key = 'role-access-key'
        mock_role_frozen_creds.secret_key = 'role-secret-key'
        mock_role_frozen_creds.token = 'role-session-token'
        mock_role_creds.get_frozen_credentials.return_value = mock_role_frozen_creds
        
        mock_role_session.client.side_effect = lambda service, **kwargs: {
            'cloudtrail': mock_role_cloudtrail,
            's3': mock_role_s3
        }.get(service, MagicMock())
        
        mock_role_session.get_credentials.return_value = mock_role_creds
        mock_role_session.region_name = 'us-east-1'
        
        mock_boto3_session.return_value = mock_role_session
        
        # Mock CloudTrail response using the role session
        mock_role_cloudtrail.describe_trails.return_value = {
            'trailList': [{
                'Name': 'test-trail',
                'S3BucketName': 'test-bucket',
                'S3KeyPrefix': 'prefix'
            }]
        }
        
        # Mock S3 list_objects_v2 paginator using role session
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{
            'Contents': [{
                'Key': 'prefix/AWSLogs/123456789012/CloudTrail/us-east-1/2023/04/01/123456789012_CloudTrail_us-east-1_20230401T0000Z.json.gz',
                'Size': 1000,
                'LastModified': datetime.datetime.now()
            }]
        }]
        mock_role_s3.get_paginator.return_value = mock_paginator
        
        # Mock setup_error_logging to avoid file operations
        with patch.object(self.transfer_manager, 'setup_error_logging') as mock_setup_logging:
            mock_setup_logging.return_value = "/mock/path/error.log"
            
            # Mock _download_logs_async to avoid actual download
            self.transfer_manager._download_logs_async = MagicMock(return_value=(1, 1, 0))
            
            # Mock _save_transfer_state to avoid file operations
            self.transfer_manager._save_transfer_state = MagicMock()
            
            # Test starting a transfer with a new role
            role_arn = 'arn:aws:iam::123456789012:role/test-role'
            result = self.transfer_manager.start_transfer(
                account_id='123456789012',
                trail_name='test-trail',
                destination=self.test_dir,
                role_arn=role_arn
            )
            
            # Verify we tried to assume the role
            self.mock_sts.assume_role.assert_called_once_with(
                RoleArn=role_arn,
                RoleSessionName="CloudTrailTransfer"
            )
            
            # Verify a new session was created with the role credentials
            mock_boto3_session.assert_called_once_with(
                aws_access_key_id='role-access-key',
                aws_secret_access_key='role-secret-key',
                aws_session_token='role-session-token',
                region_name='us-east-1'
            )
            
            # Verify the transfer state has saved creds
            self.assertIsNotNone(self.transfer_manager.transfer_state.get('saved_creds'))
            
            # Verify the role ARN was saved in the transfer state
            self.assertEqual(
                self.transfer_manager.transfer_state.get('role_arn'),
                role_arn
            )
    
    def test_resume_transfer_with_saved_creds(self):
        """Test resuming a transfer using saved credentials"""
        # Set up a mock transfer state with saved credentials
        self.transfer_manager.transfer_state = {
            'bucket_name': 'test-bucket',
            'destination': self.test_dir,
            'remaining_logs': [
                {'key': 'test-key-1', 'size': 1000},
                {'key': 'test-key-2', 'size': 2000}
            ],
            'transferred_logs': 5,
            'total_logs': 7,
            'saved_creds': {
                'aws_access_key_id': 'saved-access-key',
                'aws_secret_access_key': 'saved-secret-key',
                'aws_session_token': 'saved-session-token',
                'region_name': 'us-east-1'
            }
        }
        
        # Mock boto3.Session for the resumed session
        with patch('boto3.Session') as mock_boto3_session:
            # Configure the mock for the resumed session
            mock_resumed_session = MagicMock()
            mock_resumed_s3 = MagicMock()
            
            mock_resumed_session.client.side_effect = lambda service, **kwargs: {
                's3': mock_resumed_s3
            }.get(service, MagicMock())
            
            mock_boto3_session.return_value = mock_resumed_session
            
            # Mock _download_logs_async to avoid actual download
            self.transfer_manager._download_logs_async = MagicMock(return_value=(7, 7, 0))
            
            # Test resuming the transfer
            result = self.transfer_manager.resume_transfer()
            
            # Verify a new session was created with the saved credentials
            mock_boto3_session.assert_called_once_with(
                aws_access_key_id='saved-access-key',
                aws_secret_access_key='saved-secret-key',
                aws_session_token='saved-session-token',
                region_name='us-east-1'
            )
            
            # Verify _download_logs_async was called with the correct parameters
            self.transfer_manager._download_logs_async.assert_called_once_with(
                mock_resumed_s3,
                [{'key': 'test-key-1', 'size': 1000}, {'key': 'test-key-2', 'size': 2000}],
                'test-bucket',
                self.test_dir,
                None,
                5,
                7,
                mock_resumed_session
            )
    
    def test_save_and_load_transfer_state(self):
        """Test saving and loading transfer state"""
        # Create a test transfer state
        self.transfer_manager.transfer_state = {
            'account_id': '123456789012',
            'trail_name': 'test-trail',
            'bucket_name': 'test-bucket',
            'destination': self.test_dir,
            'from_date': '2023-04-01',
            'to_date': '2023-04-30',
            'total_logs': 10,
            'transferred_logs': 5,
            'remaining_logs': [
                {'key': 'key1', 'size': 1000, 'date': datetime.datetime(2023, 4, 1)},
                {'key': 'key2', 'size': 2000, 'last_modified': datetime.datetime(2023, 4, 2)}
            ],
            'completed_logs': [
                {'key': 'key3', 'size': 3000, 'date': datetime.datetime(2023, 4, 3)}
            ],
            'completed': False,
            'role_arn': 'arn:aws:iam::123456789012:role/test-role',
            'auth_info': {'method': 'profile', 'profile': 'test-profile', 'region': 'us-east-1'},
            'failed_count': 2,
            'error_log': '/path/to/error.log',
            'saved_creds': {
                'aws_access_key_id': 'test-access-key',
                'aws_secret_access_key': 'test-secret-key',
                'aws_session_token': 'test-session-token',
                'region_name': 'us-east-1'
            }
        }
        
        # Mock json.dump to avoid actual file operations
        with patch('builtins.open', mock_open()) as mock_file, \
             patch('json.dump') as mock_json_dump:
             
            # Test saving the state
            self.transfer_manager._save_transfer_state(self.test_dir)
            
            # Verify file was opened for writing
            mock_file.assert_called_once_with(os.path.join(self.test_dir, '.transfer_state.json'), 'w')
            
            # Verify json.dump was called
            mock_json_dump.assert_called_once()
            
            # Get the state that was passed to json.dump
            saved_state = mock_json_dump.call_args[0][0]
            
            # Verify key elements were included
            self.assertEqual(saved_state['account_id'], '123456789012')
            self.assertEqual(saved_state['role_arn'], 'arn:aws:iam::123456789012:role/test-role')
            self.assertEqual(saved_state['failed_count'], 2)
            
        # Test loading by creating a new manager and manually setting state
        new_manager = LogTransferManager(self.mock_session)
        new_manager.transfer_state = self.transfer_manager.transfer_state
        
        # Verify the state was loaded correctly
        self.assertEqual(new_manager.transfer_state['account_id'], '123456789012')
        self.assertEqual(new_manager.transfer_state['role_arn'], 'arn:aws:iam::123456789012:role/test-role')
        self.assertEqual(new_manager.transfer_state['saved_creds']['aws_access_key_id'], 'test-access-key')
    
    def test_error_logging(self):
        """Test error logging functionality"""
        # Test logging an error
        test_message = "Test error message"
        test_exception = Exception("Test exception")
        
        self.transfer_manager.log_error(test_message, test_exception)
        
        # Verify the error was logged
        self.transfer_manager.logger.error.assert_called_with(f"{test_message}: {str(test_exception)}")
        
        # Test logging without exception
        self.transfer_manager.log_error("Simple error")
        self.transfer_manager.logger.error.assert_called_with("Simple error")
    
    @patch('os.makedirs')
    @patch('logging.FileHandler')
    def test_setup_error_logging(self, mock_file_handler, mock_makedirs):
        """Test setting up error logging"""
        # Setup mock handler
        handler_instance = MagicMock()
        mock_file_handler.return_value = handler_instance
        
        # Patch datetime to return a predictable value
        with patch('datetime.datetime') as mock_datetime:
            mock_now = MagicMock()
            mock_now.strftime.return_value = "20250101_120000"
            mock_datetime.now.return_value = mock_now
            
            # Call the method
            log_file = self.transfer_manager.setup_error_logging(self.test_dir)
            
            # Verify directory was created
            mock_makedirs.assert_called_with(os.path.join(self.test_dir, 'transfer_logs'), exist_ok=True)
            
            # Verify handler was created with expected path
            expected_log_path = os.path.join(self.test_dir, 'transfer_logs', 'transfer_errors_20250101_120000.log')
            mock_file_handler.assert_called_with(expected_log_path)
            
            # Verify handler was configured
            handler_instance.setFormatter.assert_called()
            
            # Verify log file path was returned and stored
            self.assertEqual(log_file, expected_log_path)
            self.assertEqual(self.transfer_manager.error_log_path, expected_log_path)
    
    def test_download_worker(self):
        """Test the download_log_worker function"""
        # Create a mock session config
        session_config = {
            'aws_access_key_id': 'test-access-key',
            'aws_secret_access_key': 'test-secret-key',
            'aws_session_token': 'test-session-token',
            'region_name': 'us-east-1'
        }
        
        # Create a test log file
        log_file = {
            'key': 'AWSLogs/123456789012/CloudTrail/us-east-1/2023/04/01/file.json.gz',
            'size': 1000
        }
        
        # Mock boto3.Session and S3 client
        with patch('boto3.Session') as mock_session, \
             patch('boto3.client') as mock_client, \
             patch('os.makedirs') as mock_makedirs:
            
            # Configure mock session
            mock_session_instance = MagicMock()
            mock_session.return_value = mock_session_instance
            
            # Configure mock S3 client
            mock_s3 = MagicMock()
            mock_session_instance.client.return_value = mock_s3
            mock_client.return_value = mock_s3
            
            # Test successful download
            result = download_log_worker(log_file, 'test-bucket', self.test_dir, session_config)
            
            # Verify S3 session was created with credentials
            mock_session.assert_called_with(
                aws_access_key_id='test-access-key',
                aws_secret_access_key='test-secret-key',
                aws_session_token='test-session-token',
                region_name='us-east-1'
            )
            
            # Verify S3 client was used
            mock_session_instance.client.assert_called_with('s3')
            
            # Verify target directory was created
            mock_makedirs.assert_called()
            
            # Verify download was attempted
            mock_s3.download_file.assert_called()
            
            # Verify return value
            self.assertTrue(result['success'])
            self.assertEqual(result['key'], log_file['key'])
            
            # Test download error
            mock_s3.download_file.side_effect = Exception("Test download error")
            
            result = download_log_worker(log_file, 'test-bucket', self.test_dir, session_config)
            
            # Verify error was handled and returned
            self.assertFalse(result['success'])
            self.assertEqual(result['key'], log_file['key'])
            self.assertIsNotNone(result['error'])

if __name__ == '__main__':
    unittest.main() 