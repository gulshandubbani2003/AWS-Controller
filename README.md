# CloudSentinel (AWS Management Dashboard)

A comprehensive AWS management dashboard built with React frontend and Flask backend. Monitor and manage your AWS resources including EC2, RDS, Lambda, S3, VPC, and IAM with a beautiful, modern interface.
<img width="1674" height="976" alt="Screenshot 2025-08-26 at 10 49 04 AM" src="https://github.com/user-attachments/assets/4b58672f-fb4b-4d49-ac8f-4f16dc042eca" />

## Features

- **Multi-Service Monitoring**: Track EC2, RDS, Lambda, S3, VPC, and IAM resources
- **Real-time Security Analysis**: Automated security scanning and alerting
- **Beautiful UI**: Modern, responsive design with Tailwind CSS
- **Resource Management**: View detailed information about all AWS resources
- **Security Dashboard**: Monitor security alerts and compliance
- **Cross-Region Support**: Connect to any AWS region

## Screenshots
<img width="2880" height="1500" alt="Screenshot 2025-08-23 at 12 18 31 AM" src="https://github.com/user-attachments/assets/aa383af3-d855-4b1d-8f93-ac5df9f5224a" />

<img width="2854" height="1650" alt="Screenshot 2025-08-22 at 9 06 21 PM" src="https://github.com/user-attachments/assets/5ff585d8-a092-4cc3-8e9b-5b6d624544d6" />

<img width="2854" height="1650" alt="Screenshot 2025-08-22 at 10 17 03 PM" src="https://github.com/user-attachments/assets/1aedd1ef-0844-43ba-81ee-ad052eea3539" />


The dashboard provides:
- Overview dashboard with resource counts and security alerts
- Detailed EC2 instance management
- RDS database monitoring
- Lambda function analytics
- S3 bucket management
- VPC and subnet configuration
- IAM user and role management
- Security analysis and alerts

## Prerequisites

- Python 3.8+
- Node.js 16+
- AWS Account with appropriate permissions
- AWS Access Key ID and Secret Access Key

## Installation

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd aws-management-dashboard
```

### 2. Set up Python backend
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Set up React frontend
```bash
# Install Node.js dependencies
npm install
```

## Usage

### 1. Start the Flask backend
```bash
# Activate virtual environment (if not already activated)
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run the Flask server
python one.py
```

The backend will start on `http://localhost:5000`

### 2. Start the React frontend
```bash
# In a new terminal
npm run dev
```

The frontend will start on `http://localhost:3000`

### 3. Connect to AWS
1. Open your browser and navigate to `http://localhost:3000`
2. Enter your AWS Access Key ID and Secret Access Key
3. Select your preferred AWS region
4. Click "Connect to AWS"

## AWS Permissions Required

Your AWS user/role needs the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "rds:DescribeDBInstances",
                "lambda:ListFunctions",
                "s3:ListBuckets",
                "s3:GetBucketLocation",
                "s3:ListObjectsV2",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListAttachedUserPolicies",
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:DescribeAlarms",
                "logs:DescribeLogGroups",
                "logs:FilterLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        }
    ]
}
```

## Project Structure

```
aws-management-dashboard/
├── one.py                          # Flask backend server
├── requirements.txt                # Python dependencies
├── package.json                    # Node.js dependencies
├── vite.config.js                  # Vite configuration
├── tailwind.config.js             # Tailwind CSS configuration
├── postcss.config.js              # PostCSS configuration
├── index.html                      # Main HTML file
├── src/
│   ├── main.jsx                   # React entry point
│   ├── App.jsx                    # Main App component
│   ├── index.css                   # Global styles
│   └── components/
│       └── AWSManagementDashboard.jsx  # Main dashboard component
└── README.md                       # This file
```

## API Endpoints

The Flask backend provides the following API endpoints:

- `POST /api/connect` - Connect to AWS with credentials
- `GET /api/resources` - Get all AWS resources
- `GET /api/ec2` - Get EC2 instances
- `GET /api/rds` - Get RDS instances
- `GET /api/lambda` - Get Lambda functions
- `GET /api/s3` - Get S3 buckets
- `GET /api/vpc` - Get VPCs
- `GET /api/security` - Get security alerts
- `GET /api/health` - Health check

### Unified Service Controller (merged from aws-service-controller)

- `GET /api/services` — List configured applications (from `servicesMap.json`)
- `GET /api/services/:appName` — Get all services for an application
- `GET /api/services/:appName/:serviceType` — Get configured resources for a service
- `GET /api/services/:appName/:serviceType/status` — Get live status for resources
- `POST /api/services/:appName/:serviceType/start` — Start resource (EC2/RDS) or invoke (Lambda)
- `POST /api/services/:appName/:serviceType/stop` — Stop resource (EC2/RDS)
- `POST /api/services/:appName/sqs/:queueName/enable` — Enable SQS queue (test message)
- `POST /api/services/:appName/sqs/:queueName/disable` — Disable SQS queue (purge)
- `POST /api/services/:appName/lambda/:functionName/enable-concurrency` — Enable provisioned concurrency
- `POST /api/services/:appName/lambda/:functionName/disable-concurrency` — Disable provisioned concurrency
- `GET /api/services/:appName/lambda/:functionName/concurrency-status` — Provisioned concurrency status

Frontend adds a new "Service Controller" tab that surfaces these operations without altering existing pages.

## Security Features

- **Credential Management**: Secure handling of AWS credentials
- **Security Scanning**: Automated detection of security issues
- **Access Control**: IAM-based permission management
- **Audit Logging**: Comprehensive logging of all operations

## Development

### Backend Development
- The Flask backend is in `one.py`
- Add new AWS services by extending the existing functions
- Implement additional security checks in `analyze_security()`

### Frontend Development
- React components are in `src/components/`
- Styling uses Tailwind CSS
- Icons from Lucide React

### Adding New AWS Services
1. Add the service function in `one.py` (e.g., `list_elasticache_clusters()`)
2. Add the API endpoint
3. Update the frontend to display the new service
4. Add security analysis rules if applicable

## Troubleshooting

### Common Issues

1. **CORS Errors**: Ensure the Flask backend is running and CORS is enabled
2. **AWS Connection Failed**: Verify your AWS credentials and permissions
3. **Port Already in Use**: Change ports in `vite.config.js` or `one.py`
4. **Module Not Found**: Ensure all dependencies are installed

### Debug Mode
Enable debug mode in Flask by setting:
```python
app.run(debug=True, host='0.0.0.0', port=5000)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support and questions:
- Check the troubleshooting section
- Review AWS documentation for specific services
- Open an issue in the repository

## Roadmap

- [ ] CloudWatch integration for metrics
- [ ] Cost optimization recommendations
- [ ] Automated resource management
- [ ] Multi-account support
- [ ] Mobile app
- [ ] Advanced security scanning
- [ ] Backup and recovery management 
