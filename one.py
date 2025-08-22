# app.py - Flask backend based on your existing AWS code
from flask import Flask, jsonify, request
from flask_cors import CORS
import boto3
import json
import logging
from datetime import datetime
import threading
import time

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Global variables for AWS session
baseSession = None
current_credentials = {}

# Security monitoring alerts storage
security_alerts = []

def create_aws_session(access_key, secret_key, region):
    """Create AWS session with provided credentials"""
    global baseSession, current_credentials
    try:
        baseSession = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        current_credentials = {
            'access_key': access_key,
            'secret_key': secret_key,
            'region': region
        }
        return True
    except Exception as e:
        print(f"Error creating AWS session: {e}")
        return False

def list_ec2_instances():
    """Enhanced version of your EC2 listing function"""
    try:
        ec2 = baseSession.client('ec2')
        response = ec2.describe_instances()
        instances = []

        for reservation in response['Reservations']:
            for inst in reservation['Instances']:
                # Safely get name from tags
                name = 'Unnamed'
                if 'Tags' in inst and inst['Tags']:
                    for tag in inst['Tags']:
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break
                
                instances.append({
                    'name': name,
                    'instance_id': inst['InstanceId'],
                    'instance_type': inst['InstanceType'],
                    'state': inst['State']['Name'],
                    'availability_zone': inst['Placement']['AvailabilityZone'],
                    'public_ip': inst.get('PublicIpAddress', 'N/A'),
                    'private_ip': inst.get('PrivateIpAddress', 'N/A'),
                    'launch_time': inst.get('LaunchTime').isoformat() if inst.get('LaunchTime') else 'N/A',
                    'security_groups': [sg['GroupName'] for sg in inst.get('SecurityGroups', [])],
                    'vpc_id': inst.get('VpcId', 'N/A'),
                    'subnet_id': inst.get('SubnetId', 'N/A')
                })
        return instances
    except Exception as e:
        print(f"Error listing EC2 instances: {e}")
        return []

def list_s3_buckets():
    """Enhanced version of your S3 listing function"""
    try:
        s3 = baseSession.client('s3')
        response = s3.list_buckets()
        buckets = []
        
        for bucket in response['Buckets']:
            bucket_info = {
                'name': bucket['Name'],
                'creation_date': bucket['CreationDate'].isoformat(),
                'region': 'Unknown',
                'objects': 0,
                'size': '0 B'
            }
            
            try:
                # Get bucket location
                location_response = s3.get_bucket_location(Bucket=bucket['Name'])
                bucket_info['region'] = location_response.get('LocationConstraint') or 'us-east-1'
                
                # Get bucket size (simplified - in production you'd use CloudWatch)
                try:
                    objects_response = s3.list_objects_v2(Bucket=bucket['Name'], MaxKeys=1000)
                    bucket_info['objects'] = objects_response.get('KeyCount', 0)
                    
                    total_size = sum(obj.get('Size', 0) for obj in objects_response.get('Contents', []))
                    bucket_info['size'] = format_size(total_size)
                except:
                    bucket_info['objects'] = 'Access Denied'
                    bucket_info['size'] = 'Access Denied'
                    
            except Exception as e:
                print(f"Error getting bucket details for {bucket['Name']}: {e}")
            
            buckets.append(bucket_info)
        return buckets
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
        return []

def list_rds_instances():
    """Enhanced version of your RDS listing function"""
    try:
        rds = baseSession.client('rds')
        response = rds.describe_db_instances()
        instances = []
        
        for inst in response['DBInstances']:
            instances.append({
                'name': inst['DBInstanceIdentifier'],
                'engine': inst['Engine'],
                'engine_version': inst.get('EngineVersion', 'N/A'),
                'state': inst['DBInstanceStatus'],
                'instance_class': inst['DBInstanceClass'],
                'allocated_storage': inst.get('AllocatedStorage', 0),
                'multi_az': inst.get('MultiAZ', False),
                'publicly_accessible': inst.get('PubliclyAccessible', False),
                'backup_retention': inst.get('BackupRetentionPeriod', 0),
                'vpc_id': inst.get('DBSubnetGroup', {}).get('VpcId', 'N/A')
            })
        return instances
    except Exception as e:
        print(f"Error listing RDS instances: {e}")
        return []

def list_lambda_functions():
    """Enhanced version of your Lambda listing function"""
    try:
        lambda_client = baseSession.client('lambda')
        response = lambda_client.list_functions()
        functions = []
        
        for func in response['Functions']:
            functions.append({
                'name': func.get('FunctionName', 'N/A'),
                'runtime': func.get('Runtime', 'N/A'),
                'state': func.get('State', 'Active'),
                'last_modified': func.get('LastModified', 'N/A'),
                'timeout': func.get('Timeout', 0),
                'memory_size': func.get('MemorySize', 0),
                'code_size': func.get('CodeSize', 0),
                'handler': func.get('Handler', 'N/A'),
                'role': func.get('Role', 'N/A').split('/')[-1] if func.get('Role') else 'N/A'
            })
        return functions
    except Exception as e:
        print(f"Error listing Lambda functions: {e}")
        return []

def list_iam_users():
    """Enhanced version of your IAM users listing function"""
    try:
        iam = baseSession.client('iam')
        response = iam.list_users()
        users = []
        
        for user in response['Users']:
            user_info = {
                'name': user['UserName'],
                'arn': user['Arn'],
                'creation_date': user['CreateDate'].isoformat(),
                'password_last_used': user.get('PasswordLastUsed', 'Never').isoformat() if isinstance(user.get('PasswordLastUsed'), datetime) else 'Never',
                'path': user.get('Path', '/'),
                'user_id': user.get('UserId', 'N/A')
            }
            
            # Get user policies count
            try:
                policies_response = iam.list_attached_user_policies(UserName=user['UserName'])
                user_info['attached_policies'] = len(policies_response['AttachedPolicies'])
            except:
                user_info['attached_policies'] = 0
            
            users.append(user_info)
        return users
    except Exception as e:
        print(f"Error listing IAM users: {e}")
        return []

def list_iam_roles():
    """Enhanced version of your IAM roles listing function"""
    try:
        iam = baseSession.client('iam')
        response = iam.list_roles()
        roles = []
        
        for role in response['Roles']:
            roles.append({
                'name': role['RoleName'],
                'arn': role['Arn'],
                'creation_date': role['CreateDate'].isoformat(),
                'path': role.get('Path', '/'),
                'max_session_duration': role.get('MaxSessionDuration', 3600),
                'description': role.get('Description', 'No description')
            })
        return roles
    except Exception as e:
        print(f"Error listing IAM roles: {e}")
        return []

def list_vpc():
    """Enhanced version of your VPC listing function"""
    try:
        ec2 = baseSession.client('ec2')
        response = ec2.describe_vpcs()
        vpcs = []
        
        for vpc in response['Vpcs']:
            # Safely get name from tags
            name = 'Unnamed VPC'
            if 'Tags' in vpc and vpc['Tags']:
                for tag in vpc['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
            
            # Get subnet count
            subnets_response = ec2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
            )
            subnet_count = len(subnets_response['Subnets'])
            
            vpcs.append({
                'name': name,
                'id': vpc['VpcId'],
                'cidr_block': vpc['CidrBlock'],
                'state': vpc['State'],
                'is_default': vpc.get('IsDefault', False),
                'subnet_count': subnet_count
            })
        return vpcs
    except Exception as e:
        print(f"Error listing VPCs: {e}")
        return []

def list_subnets():
    """Enhanced version of your subnet listing function"""
    try:
        ec2 = baseSession.client('ec2')
        response = ec2.describe_subnets()
        subnets = []
        
        for subnet in response['Subnets']:
            # Safely get name from tags
            name = 'Unnamed Subnet'
            if 'Tags' in subnet and subnet['Tags']:
                for tag in subnet['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
            
            subnets.append({
                'name': name,
                'id': subnet['SubnetId'],
                'vpc_id': subnet['VpcId'],
                'cidr_block': subnet['CidrBlock'],
                'availability_zone': subnet['AvailabilityZone'],
                'available_ip_count': subnet['AvailableIpAddressCount'],
                'state': subnet['State'],
                'map_public_ip': subnet.get('MapPublicIpOnLaunch', False)
            })
        return subnets
    except Exception as e:
        print(f"Error listing subnets: {e}")
        return []

def format_size(size_bytes):
    """Format bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.2f} {size_names[i]}"

def analyze_security():
    """Basic security analysis"""
    global security_alerts
    security_alerts = []
    
    try:
        # Check for public EC2 instances
        instances = list_ec2_instances()
        for instance in instances:
            if instance.get('public_ip') and instance['public_ip'] != 'N/A':
                if instance['state'] == 'running':
                    security_alerts.append({
                        'severity': 'medium',
                        'message': f"EC2 instance '{instance['name']}' has public IP address",
                        'service': 'EC2',
                        'resource': instance['instance_id'],
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Check for publicly accessible RDS instances
        rds_instances = list_rds_instances()
        for db in rds_instances:
            if db.get('publicly_accessible'):
                security_alerts.append({
                    'severity': 'high',
                    'message': f"RDS instance '{db['name']}' is publicly accessible",
                    'service': 'RDS',
                    'resource': db['name'],
                    'timestamp': datetime.now().isoformat()
                })
        
        # Check S3 bucket security (simplified)
        buckets = list_s3_buckets()
        for bucket in buckets:
            # This is a simplified check - in production you'd check bucket policies
            security_alerts.append({
                'severity': 'low',
                'message': f"Review S3 bucket '{bucket['name']}' permissions",
                'service': 'S3',
                'resource': bucket['name'],
                'timestamp': datetime.now().isoformat()
            })
            
    except Exception as e:
        print(f"Error during security analysis: {e}")
    
    return security_alerts

# API Routes
@app.route('/api/connect', methods=['POST'])
def connect_aws():
    """Connect to AWS with provided credentials"""
    data = request.json
    access_key = data.get('accessKey')
    secret_key = data.get('secretKey')
    region = data.get('region', 'us-east-1')
    
    if create_aws_session(access_key, secret_key, region):
        # Run initial security analysis
        threading.Thread(target=analyze_security).start()
        return jsonify({'success': True, 'message': 'Connected successfully'})
    else:
        return jsonify({'success': False, 'message': 'Failed to connect'}), 400

@app.route('/api/resources', methods=['GET'])
def get_all_resources():
    """Get all AWS resources"""
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    
    try:
        resources = {
            'ec2': list_ec2_instances(),
            'rds': list_rds_instances(),
            'lambda': list_lambda_functions(),
            's3': list_s3_buckets(),
            'vpc': list_vpc(),
            'subnets': list_subnets(),
            'iam_users': list_iam_users(),
            'iam_roles': list_iam_roles(),
            'security_alerts': security_alerts
        }
        return jsonify(resources)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ec2', methods=['GET'])
def get_ec2_instances():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_ec2_instances())

@app.route('/api/s3', methods=['GET'])
def get_s3_buckets():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_s3_buckets())

@app.route('/api/rds', methods=['GET'])
def get_rds_instances():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_rds_instances())

@app.route('/api/lambda', methods=['GET'])
def get_lambda_functions():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_lambda_functions())

@app.route('/api/vpc', methods=['GET'])
def get_vpcs():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_vpc())

@app.route('/api/security', methods=['GET'])
def get_security_alerts():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(security_alerts)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'connected': baseSession is not None})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)