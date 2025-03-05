# CloudTrail Log Explorer

## Overview

The CloudTrail Log Explorer is a Python-based GUI application designed to simplify the process of discovering, downloading, and managing AWS CloudTrail logs. It provides an intuitive graphical interface built with Tkinter, allowing users to easily authenticate with AWS, assume roles, and transfer logs from S3 buckets.

## Features

- **AWS Authentication**: Supports authentication via AWS profiles or direct API keys.
- **Role Management**: Automatically detects and assumes AWS IAM roles, preventing redundant role assumptions.
- **Log Discovery**: Scans and identifies CloudTrail logs within specified date ranges.
- **Log Transfer**: Efficiently downloads CloudTrail logs from S3 buckets using multiprocessing.
- **Resume Capability**: Allows resuming interrupted transfers without rescanning the entire bucket.
- **Error Logging and Tracking**: Comprehensive logging of errors and failed transfers, with detailed reports.
- **User-Friendly GUI**: Real-time progress updates, error notifications, and easy access to logs.

## Installation

### Prerequisites

- Python 3.8 or higher
- AWS CLI configured with appropriate permissions

### Dependencies

Install required Python packages:

```bash
pip install boto3
```

## Usage

### Starting the Application

Run the application from your terminal:

```bash
python gui.py
```

## Using the Application

### Step 1: Authenticate

- Choose your authentication method:
  - **AWS Profile**: Select a profile from your AWS credentials.
  - **API Keys**: Enter your AWS Access Key ID and Secret Access Key.

### Step 2: Select CloudTrail Logs

- Enter the AWS Account ID and CloudTrail trail name.
- Optionally specify a date range to filter logs.

### Step 2: Assume Role (Optional)

- Enter the ARN of the role you wish to assume (optional).

### Step 3: Start Transfer

- Select the destination folder for downloaded logs.
- Click "Start Transfer" to begin downloading.

### Step 4: Monitor Progress

- View real-time progress and status updates.
- If errors occur, click "View Error Logs" to inspect detailed logs.

### Step 5: Resume Transfer

- If a transfer is interrupted, restart the application and click "Resume Transfer" to continue.

## Examples

### Example: Starting a Transfer

1. Authenticate using your AWS profile.
2. Enter the AWS account ID and CloudTrail trail name.
3. Choose a date range (optional).
4. Click "Start Transfer".

### Example: Resuming a Transfer

- If a transfer is interrupted, simply reopen the application and click "Resume Transfer". The application will continue from where it left off.

## Troubleshooting

- **Role Assumption Errors**: Ensure the role you're trying to assume has the correct trust relationships and permissions.
- **403 Forbidden Errors**: Verify your AWS credentials and permissions for accessing the S3 bucket.
- **Logs and Reports**: Check the `transfer_logs` directory in your destination folder for detailed error logs and failed transfer reports.

## Contributing

Feel free to contribute by opening issues or submitting pull requests. Your feedback and contributions are welcome!

## License

This project is licensed under the MIT License. 