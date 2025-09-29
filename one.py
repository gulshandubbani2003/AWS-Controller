# app.py - Flask backend based on your existing AWS code
from flask import Flask, jsonify, request
import boto3
import json
import logging
from datetime import datetime, timedelta
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

app = Flask(__name__)

# Initialize AWS session for Lambda deployment
baseSession = None
current_credentials = None

# Auto-initialize AWS session when running in Lambda
def initialize_aws_session():
    global baseSession
    if baseSession is None:
        try:
            # Use default region from environment or ap-south-1
            region = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION') or 'ap-south-1'
            baseSession = boto3.Session(region_name=region)
            print(f"AWS session initialized with region: {region}")
        except Exception as e:
            print(f"Error initializing AWS session: {e}")

# Initialize session on module load
initialize_aws_session()

# Ensure a session exists for request handlers that might be hit before explicit connect
def ensure_session():
    if baseSession is None:
        initialize_aws_session()

# FINAL CORS HANDLER: explicit origin matching and OPTIONS short-circuit
ALLOWED_ORIGINS = {
    'https://aws-controller.vercel.app',
    'https://cloudsentinel.vercel.app',
    'http://localhost:3000'
}

@app.before_request
def cors_preflight():
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin', '*')
        allow_origin = origin if origin in ALLOWED_ORIGINS else '*'
        resp = jsonify({})
        resp.headers['Access-Control-Allow-Origin'] = allow_origin
        resp.headers['Vary'] = 'Origin'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = request.headers.get('Access-Control-Request-Headers', 'Content-Type, Authorization')
        return resp

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin:
        allow_origin = origin if origin in ALLOWED_ORIGINS else '*'
        response.headers['Access-Control-Allow-Origin'] = allow_origin
        response.headers['Vary'] = 'Origin'
        response.headers.setdefault('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        response.headers.setdefault('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    else:
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers.setdefault('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        response.headers.setdefault('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    return response

# Global variables for AWS session
baseSession = None
current_credentials = {}

# Security monitoring alerts storage
security_alerts = []

# Services map for controller features (merged from aws-service-controller)
services_map = {}
try:
    services_map_path = os.path.join(os.path.dirname(__file__), 'servicesMap.json')
    with open(services_map_path, 'r') as f:
        services_map = json.load(f)
except Exception as e:
    print(f"Warning: could not load servicesMap.json: {e}")

def _parse_resource_id(resource: object) -> str:
    """Extract the concrete AWS identifier from entries like 'name:i-1234' or dicts."""
    if isinstance(resource, str):
        return resource.split(':', 1)[1] if ':' in resource else resource
    if isinstance(resource, dict):
        return resource.get('id') or resource.get('name') or ''
    return str(resource)

def _find_queue_url(sqs_client, queue_name: str) -> str | None:
    try:
        resp = sqs_client.list_queues(QueueNamePrefix=queue_name)
        for url in resp.get('QueueUrls', []):
            last = url.rsplit('/', 1)[-1]
            if last == queue_name or queue_name in url:
                return url
    except Exception as err:
        print(f"Error listing queues: {err}")
    return None

def _get_latest_lambda_version(lambda_client, function_name: str) -> str | None:
    try:
        resp = lambda_client.list_versions_by_function(FunctionName=function_name)
        versions = [v for v in resp.get('Versions', []) if v.get('Version') != '$LATEST']
        if not versions:
            return None
        versions.sort(key=lambda v: int(v['Version']), reverse=True)
        return versions[0]['Version']
    except Exception as err:
        print(f"Error getting latest lambda version: {err}")
        return None

def create_aws_session(access_key, secret_key, region):
    """Create AWS session with provided credentials"""
    global baseSession, current_credentials
    try:
        # If no explicit keys are provided (e.g., running in Lambda), fall back to role-based creds
        if not access_key or not secret_key:
            baseSession = boto3.Session(region_name=region)
        else:
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

def _gather_resources_parallel():
    """Fetch resource groups in parallel to reduce overall latency (Lambda-friendly)."""
    work: dict[str, callable] = {
        'ec2': list_ec2_instances,
        'rds': list_rds_instances,
        'lambda': list_lambda_functions,
        's3': list_s3_buckets,
        'vpc': list_vpc,
        'subnets': list_subnets,
        'iam_users': list_iam_users,
        'iam_roles': list_iam_roles,
        'cloudwatch_metrics': get_cloudwatch_metrics,
        'cloudwatch_logs': get_cloudwatch_logs,
        'cloudwatch_alarms': get_cloudwatch_alarms,
    }
    results = { 'security_alerts': security_alerts }
    # Use a moderate pool size to stay within Lambda CPU limits
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_key = { executor.submit(fn): key for key, fn in work.items() }
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
            except Exception as err:
                print(f"Error fetching {key}: {err}")
                # Return empty on failure to avoid blocking UI
                results[key] = [] if key not in ('cloudwatch_metrics', 'cloudwatch_logs', 'cloudwatch_alarms') else {}
    return results

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
                'package_type': func.get('PackageType', 'Image' if 'ImageConfig' in func or func.get('PackageType') == 'Image' else 'Zip'),
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

def get_cloudwatch_metrics():
    """Get CloudWatch metrics for various AWS services"""
    try:
        cloudwatch = baseSession.client('cloudwatch')
        metrics_data = {}
        
        # Get EC2 CPU utilization metrics for actual instances
        try:
            instances = list_ec2_instances()
            ec2_cpu_data = []
            
            for instance in instances[:3]:  # Limit to first 3 instances to avoid API limits
                if instance['state'] == 'running':
                    try:
                        response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance['instance_id']}],
                            StartTime=datetime.now() - timedelta(hours=1),
                            EndTime=datetime.now(),
                            Period=300,
                            Statistics=['Average', 'Maximum']
                        )
                        
                        if response['Datapoints']:
                            for datapoint in response['Datapoints']:
                                datapoint['InstanceName'] = instance['name']
                                datapoint['InstanceId'] = instance['instance_id']
                            ec2_cpu_data.extend(response['Datapoints'])
                    except Exception as e:
                        print(f"Error getting metrics for instance {instance['instance_id']}: {e}")
                        continue
            
            metrics_data['ec2_cpu'] = ec2_cpu_data
        except Exception as e:
            print(f"Error getting EC2 metrics: {e}")
            metrics_data['ec2_cpu'] = []
        
        # Get RDS CPU utilization for actual databases
        try:
            rds_instances = list_rds_instances()
            rds_cpu_data = []
            
            for db in rds_instances[:3]:  # Limit to first 3 databases
                if db['state'] == 'available':
                    try:
                        response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/RDS',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['name']}],
                            StartTime=datetime.now() - timedelta(hours=1),
                            EndTime=datetime.now(),
                            Period=300,
                            Statistics=['Average', 'Maximum']
                        )
                        
                        if response['Datapoints']:
                            for datapoint in response['Datapoints']:
                                datapoint['DBName'] = db['name']
                                datapoint['Engine'] = db['engine']
                            rds_cpu_data.extend(response['Datapoints'])
                    except Exception as e:
                        print(f"Error getting metrics for RDS {db['name']}: {e}")
                        continue
            
            metrics_data['rds_cpu'] = rds_cpu_data
        except Exception as e:
            print(f"Error getting RDS metrics: {e}")
            metrics_data['rds_cpu'] = []
        
        # Get Lambda duration metrics for actual functions
        try:
            lambda_functions = list_lambda_functions()
            lambda_duration_data = []
            
            for func in lambda_functions[:3]:  # Limit to first 3 functions
                try:
                    response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Duration',
                        Dimensions=[{'Name': 'FunctionName', 'Value': func['name']}],
                        StartTime=datetime.now() - timedelta(hours=1),
                        EndTime=datetime.now(),
                        Period=300,
                        Statistics=['Average', 'Maximum']
                    )
                    
                    if response['Datapoints']:
                        for datapoint in response['Datapoints']:
                            datapoint['FunctionName'] = func['name']
                            datapoint['Runtime'] = func['runtime']
                        lambda_duration_data.extend(response['Datapoints'])
                except Exception as e:
                    print(f"Error getting metrics for Lambda {func['name']}: {e}")
                    continue
            
            metrics_data['lambda_duration'] = lambda_duration_data
        except Exception as e:
            print(f"Error getting Lambda metrics: {e}")
            metrics_data['lambda_duration'] = []
        
        return metrics_data
    except Exception as e:
        print(f"Error getting CloudWatch metrics: {e}")
        return {}

def check_cloudwatch_security():
    """Check CloudWatch for security-related events and alerts"""
    security_alerts = []
    
    try:
        cloudwatch = baseSession.client('cloudwatch')
        logs = baseSession.client('logs')
        
        # Check for high CPU usage (potential DDoS or resource abuse)
        try:
            # Get EC2 instances with high CPU
            instances = list_ec2_instances()
            for instance in instances:
                if instance['state'] == 'running':
                    try:
                        cpu_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance['instance_id']}],
                            StartTime=datetime.now() - timedelta(hours=1),
                            EndTime=datetime.now(),
                            Period=300,
                            Statistics=['Average']
                        )
                        
                        if cpu_response['Datapoints']:
                            avg_cpu = cpu_response['Datapoints'][0]['Average']
                            if avg_cpu > 90:
                                security_alerts.append({
                                    'severity': 'medium',
                                    'message': f"EC2 instance '{instance['name']}' has high CPU usage ({avg_cpu:.1f}%)",
                                    'service': 'CloudWatch',
                                    'resource': instance['instance_id'],
                                    'timestamp': datetime.now().isoformat()
                                })
                    except:
                        pass
        except Exception as e:
            print(f"Error checking EC2 CPU metrics: {e}")
        
        # Check for unusual network activity
        try:
            for instance in instances:
                if instance['state'] == 'running':
                    try:
                        network_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='NetworkIn',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance['instance_id']}],
                            StartTime=datetime.now() - timedelta(hours=1),
                            EndTime=datetime.now(),
                            Period=300,
                            Statistics=['Sum']
                        )
                        
                        if network_response['Datapoints']:
                            network_in = network_response['Datapoints'][0]['Sum']
                            # Alert if network traffic is unusually high (threshold: 1GB per 5 minutes)
                            if network_in > 1073741824:  # 1GB in bytes
                                security_alerts.append({
                                    'severity': 'high',
                                    'message': f"EC2 instance '{instance['name']}' has unusually high network traffic",
                                    'service': 'CloudWatch',
                                    'resource': instance['instance_id'],
                                    'timestamp': datetime.now().isoformat()
                                })
                    except:
                        pass
        except Exception as e:
            print(f"Error checking network metrics: {e}")
        
        # Check for failed Lambda executions
        try:
            lambda_functions = list_lambda_functions()
            for func in lambda_functions:
                try:
                    error_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Errors',
                        Dimensions=[{'Name': 'FunctionName', 'Value': func['name']}],
                        StartTime=datetime.now() - timedelta(hours=1),
                        EndTime=datetime.now(),
                        Period=300,
                        Statistics=['Sum']
                    )
                    
                    if error_response['Datapoints']:
                        error_count = error_response['Datapoints'][0]['Sum']
                        if error_count > 5:  # Alert if more than 5 errors in 5 minutes
                            security_alerts.append({
                                'severity': 'medium',
                                'message': f"Lambda function '{func['name']}' has {error_count} errors",
                                'service': 'CloudWatch',
                                'resource': func['name'],
                                'timestamp': datetime.now().isoformat()
                            })
                except:
                    pass
        except Exception as e:
            print(f"Error checking Lambda error metrics: {e}")
        
        # Check for RDS performance issues
        try:
            rds_instances = list_rds_instances()
            for db in rds_instances:
                try:
                    rds_cpu_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['name']}],
                        StartTime=datetime.now() - timedelta(hours=1),
                        EndTime=datetime.now(),
                        Period=300,
                        Statistics=['Average']
                    )
                    
                    if rds_cpu_response['Datapoints']:
                        avg_cpu = rds_cpu_response['Datapoints'][0]['Average']
                        if avg_cpu > 80:
                            security_alerts.append({
                                'severity': 'medium',
                                'message': f"RDS instance '{db['name']}' has high CPU usage ({avg_cpu:.1f}%)",
                                'service': 'CloudWatch',
                                'resource': db['name'],
                                'timestamp': datetime.now().isoformat()
                            })
                except:
                    pass
        except Exception as e:
            print(f"Error checking RDS metrics: {e}")
        
    except Exception as e:
        print(f"Error during CloudWatch security check: {e}")
    
    return security_alerts

def get_cloudwatch_logs():
    """Get recent CloudWatch logs for monitoring"""
    try:
        logs = baseSession.client('logs')
        log_data = {}
        
        # Get recent log events from CloudWatch Logs
        try:
            # Get available log groups
            log_groups_response = logs.describe_log_groups(limit=10)
            log_data['log_groups'] = log_groups_response['logGroups']
            
            # Get recent log events from multiple log groups
            all_events = []
            for log_group in log_groups_response['logGroups'][:3]:  # Limit to first 3 log groups
                try:
                    log_events_response = logs.filter_log_events(
                        logGroupName=log_group['logGroupName'],
                        startTime=int((datetime.now() - timedelta(hours=1)).timestamp() * 1000),
                        endTime=int(datetime.now().timestamp() * 1000),
                        limit=5
                    )
                    
                    if log_events_response['events']:
                        for event in log_events_response['events']:
                            event['logGroupName'] = log_group['logGroupName']
                        all_events.extend(log_events_response['events'])
                except Exception as e:
                    print(f"Error getting logs from {log_group['logGroupName']}: {e}")
                    continue
            
            # Sort events by timestamp and take the most recent
            all_events.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            log_data['recent_events'] = all_events[:10]  # Limit to 10 most recent events
            
        except Exception as e:
            print(f"Error getting log groups: {e}")
            log_data['log_groups'] = []
            log_data['recent_events'] = []
        
        return log_data
    except Exception as e:
        print(f"Error getting CloudWatch logs: {e}")
        return {}

def get_cloudwatch_alarms():
    """Get CloudWatch alarms for monitoring"""
    try:
        cloudwatch = baseSession.client('cloudwatch')
        alarms_data = {}
        
        # Get all CloudWatch alarms
        try:
            alarms_response = cloudwatch.describe_alarms()
            alarms_data['alarms'] = alarms_response['MetricAlarms']
            
            # Get alarm history for the last hour
            if alarms_response['MetricAlarms']:
                try:
                    history_response = cloudwatch.describe_alarm_history(
                        StartDate=datetime.now() - timedelta(hours=1),
                        EndDate=datetime.now(),
                        MaxRecords=10
                    )
                    alarms_data['recent_history'] = history_response['AlarmHistoryItems']
                except Exception as e:
                    print(f"Error getting alarm history: {e}")
                    alarms_data['recent_history'] = []
        except Exception as e:
            print(f"Error getting alarms: {e}")
            alarms_data['alarms'] = []
            alarms_data['recent_history'] = []
        
        return alarms_data
    except Exception as e:
        print(f"Error getting CloudWatch alarms: {e}")
        return {}

def analyze_security():
    """Enhanced security analysis with CloudWatch monitoring"""
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
        
        # Check CloudWatch for security events
        cloudwatch_alerts = check_cloudwatch_security()
        security_alerts.extend(cloudwatch_alerts)
            
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
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    
    try:
        # Parallelize to reduce latency and avoid Lambda timeouts
        resources = _gather_resources_parallel()
        return jsonify(resources)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ec2', methods=['GET'])
def get_ec2_instances():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_ec2_instances())

@app.route('/api/s3', methods=['GET'])
def get_s3_buckets():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_s3_buckets())

@app.route('/api/rds', methods=['GET'])
def get_rds_instances():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_rds_instances())

@app.route('/api/lambda', methods=['GET'])
def get_lambda_functions():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_lambda_functions())

@app.route('/api/vpc', methods=['GET'])
def get_vpcs():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(list_vpc())

@app.route('/api/security', methods=['GET'])
def get_security_alerts():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    return jsonify(security_alerts)

@app.route('/api/cloudwatch/metrics', methods=['GET'])
def get_metrics():
    """Get CloudWatch metrics"""
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        metrics = get_cloudwatch_metrics()
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloudwatch/logs', methods=['GET'])
def get_logs():
    """Get CloudWatch logs"""
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        logs = get_cloudwatch_logs()
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloudwatch/security', methods=['GET'])
def get_cloudwatch_security_alerts():
    """Get CloudWatch security alerts"""
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        alerts = check_cloudwatch_security()
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloudwatch/alarms', methods=['GET'])
def get_alarms():
    """Get CloudWatch alarms"""
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        alarms = get_cloudwatch_alarms()
        return jsonify(alarms)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'connected': baseSession is not None})

# -----------------------------
# Unified Service Controller API
# -----------------------------

@app.route('/api/services', methods=['GET'])
def list_applications():
    if not services_map:
        return jsonify({'applications': [], 'total': 0})
    applications = list(services_map.keys())
    return jsonify({'applications': applications, 'total': len(applications)})

@app.route('/api/services/<appName>', methods=['GET'])
def get_application_services(appName: str):
    app_services = services_map.get(appName)
    if not app_services:
        return jsonify({'error': 'Application not found'}), 404
    return jsonify({'application': appName, 'services': app_services})

@app.route('/api/services/<appName>/<serviceType>', methods=['GET'])
def get_service_details_for_app(appName: str, serviceType: str):
    app_services = services_map.get(appName)
    if not app_services:
        return jsonify({'error': 'Application not found'}), 404
    service_details = app_services.get(serviceType)
    if not service_details:
        return jsonify({'error': 'Service type not found'}), 404
    return jsonify({'application': appName, 'serviceType': serviceType, 'resources': service_details})

@app.route('/api/services/<appName>/<serviceType>/status', methods=['GET'])
def get_service_status(appName: str, serviceType: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    app_services = services_map.get(appName)
    if not app_services:
        return jsonify({'error': 'Application not found'}), 404
    service_details = app_services.get(serviceType)
    if not service_details:
        return jsonify({'error': 'Service type not found'}), 404

    results = []
    try:
        if serviceType == 'ec2':
            ec2 = baseSession.client('ec2')
            for resource in service_details:
                rid = _parse_resource_id(resource)
                try:
                    resp = ec2.describe_instances(InstanceIds=[rid])
                    inst = resp['Reservations'][0]['Instances'][0]
                    state = inst['State']['Name']
                    results.append({
                        'resourceId': rid,
                        'status': {
                            'instanceId': rid,
                            'status': state,
                            'health': 'healthy' if state == 'running' else 'unhealthy',
                            'uptime': int((datetime.now(inst.get('LaunchTime').tzinfo) - inst['LaunchTime']).total_seconds() // 86400) if inst.get('LaunchTime') else 0
                        },
                        'lastChecked': datetime.now().isoformat()
                    })
                except Exception as err:
                    print(f"Error getting EC2 status for {rid}: {err}")
                    results.append({'resourceId': rid, 'status': 'error', 'error': str(err), 'lastChecked': datetime.now().isoformat()})

        elif serviceType == 'lambda':
            lam = baseSession.client('lambda')
            for resource in service_details:
                fname = _parse_resource_id(resource)
                try:
                    conf = lam.get_function(FunctionName=fname)['Configuration']
                    state = conf.get('State', 'Unknown')
                    results.append({
                        'resourceId': fname,
                        'status': {
                            'functionName': fname,
                            'status': state,
                            'health': 'healthy' if state == 'Active' else 'unhealthy',
                            'lastModified': conf.get('LastModified'),
                            'memorySize': conf.get('MemorySize'),
                            'timeout': conf.get('Timeout')
                        },
                        'lastChecked': datetime.now().isoformat()
                    })
                except Exception as err:
                    print(f"Error getting Lambda status for {fname}: {err}")
                    results.append({'resourceId': fname, 'status': 'error', 'error': str(err), 'lastChecked': datetime.now().isoformat()})

        elif serviceType == 'rds':
            rds = baseSession.client('rds')
            for resource in service_details:
                dbid = _parse_resource_id(resource)
                try:
                    resp = rds.describe_db_instances(DBInstanceIdentifier=dbid)
                    inst = resp['DBInstances'][0]
                    state = inst['DBInstanceStatus']
                    results.append({
                        'resourceId': dbid,
                        'status': {
                            'dbInstanceIdentifier': dbid,
                            'status': state,
                            'health': 'healthy' if state == 'available' else 'unhealthy',
                            'engine': inst.get('Engine'),
                            'engineVersion': inst.get('EngineVersion')
                        },
                        'lastChecked': datetime.now().isoformat()
                    })
                except Exception as err:
                    print(f"Error getting RDS status for {dbid}: {err}")
                    results.append({'resourceId': dbid, 'status': 'error', 'error': str(err), 'lastChecked': datetime.now().isoformat()})

        elif serviceType == 'sqs':
            sqs = baseSession.client('sqs')
            for resource in service_details:
                qname = _parse_resource_id(resource)
                try:
                    qurl = _find_queue_url(sqs, qname)
                    if not qurl:
                        results.append({'resourceId': qname, 'status': {'status': 'unknown', 'health': 'unknown', 'message': 'Queue not found'}})
                        continue
                    attrs = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=['ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible', 'ApproximateNumberOfMessagesDelayed', 'CreatedTimestamp', 'LastModifiedTimestamp'])['Attributes']
                    not_visible = int(attrs.get('ApproximateNumberOfMessagesNotVisible', '0'))
                    results.append({
                        'resourceId': qname,
                        'status': {
                            'queueName': qname,
                            'queueUrl': qurl,
                            'approximateNumberOfMessages': int(attrs.get('ApproximateNumberOfMessages', '0')),
                            'approximateNumberOfMessagesNotVisible': not_visible,
                            'approximateNumberOfMessagesDelayed': int(attrs.get('ApproximateNumberOfMessagesDelayed', '0')),
                            'createdTimestamp': attrs.get('CreatedTimestamp'),
                            'lastModifiedTimestamp': attrs.get('LastModifiedTimestamp'),
                            'health': 'healthy' if not_visible < 100 else 'warning',
                            'status': 'available'
                        },
                        'lastChecked': datetime.now().isoformat()
                    })
                except Exception as err:
                    print(f"Error getting SQS status for {qname}: {err}")
                    results.append({'resourceId': qname, 'status': 'error', 'error': str(err), 'lastChecked': datetime.now().isoformat()})
        else:
            return jsonify({'error': 'Service type not supported'}), 400

        return jsonify({'application': appName, 'serviceType': serviceType, 'resources': results, 'lastChecked': datetime.now().isoformat()})
    except Exception as e:
        print(f"Error fetching service status: {e}")
        return jsonify({'error': 'Failed to fetch service status'}), 500

@app.route('/api/services/<appName>/<serviceType>/start', methods=['POST'])
def start_service_resource(appName: str, serviceType: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    data = request.json or {}
    resource_id = data.get('resourceId')
    if not resource_id:
        return jsonify({'error': 'resourceId is required'}), 400
    try:
        if serviceType == 'ec2':
            ec2 = baseSession.client('ec2')
            resp = ec2.start_instances(InstanceIds=[resource_id])
            return jsonify({'success': True, 'application': appName, 'serviceType': serviceType, 'resourceId': resource_id, 'result': resp.get('StartingInstances', [])})
        if serviceType == 'rds':
            rds = baseSession.client('rds')
            resp = rds.start_db_instance(DBInstanceIdentifier=resource_id)
            return jsonify({'success': True, 'application': appName, 'serviceType': serviceType, 'resourceId': resource_id, 'result': {'status': resp['DBInstance']['DBInstanceStatus']}})
        if serviceType == 'lambda':
            lam = baseSession.client('lambda')
            payload = data.get('payload', {})
            resp = lam.invoke(FunctionName=resource_id, Payload=json.dumps(payload).encode('utf-8'))
            raw = resp.get('Payload').read() if resp.get('Payload') else b''
            parsed = None
            try:
                parsed = json.loads(raw.decode('utf-8')) if raw else None
            except Exception:
                parsed = raw.decode('utf-8') if raw else None
            return jsonify({'success': True, 'application': appName, 'serviceType': serviceType, 'resourceId': resource_id, 'result': {'statusCode': resp.get('StatusCode'), 'payload': parsed, 'functionError': resp.get('FunctionError')}})
        return jsonify({'error': 'Start operation not supported for this service type'}), 400
    except Exception as e:
        print(f"Error starting service resource: {e}")
        return jsonify({'error': 'Failed to start service', 'details': str(e)}), 500

@app.route('/api/services/<appName>/<serviceType>/stop', methods=['POST'])
def stop_service_resource(appName: str, serviceType: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    data = request.json or {}
    resource_id = data.get('resourceId')
    if not resource_id:
        return jsonify({'error': 'resourceId is required'}), 400
    try:
        if serviceType == 'ec2':
            ec2 = baseSession.client('ec2')
            resp = ec2.stop_instances(InstanceIds=[resource_id])
            return jsonify({'success': True, 'application': appName, 'serviceType': serviceType, 'resourceId': resource_id, 'result': resp.get('StoppingInstances', [])})
        if serviceType == 'rds':
            rds = baseSession.client('rds')
            resp = rds.stop_db_instance(DBInstanceIdentifier=resource_id)
            return jsonify({'success': True, 'application': appName, 'serviceType': serviceType, 'resourceId': resource_id, 'result': {'status': resp['DBInstance']['DBInstanceStatus']}})
        return jsonify({'error': 'Stop operation not supported for this service type'}), 400
    except Exception as e:
        print(f"Error stopping service resource: {e}")
        return jsonify({'error': 'Failed to stop service', 'details': str(e)}), 500

@app.route('/api/services/<appName>/sqs/<queueName>/enable', methods=['POST'])
def enable_queue(appName: str, queueName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        sqs = baseSession.client('sqs')
        qurl = _find_queue_url(sqs, queueName)
        if not qurl:
            return jsonify({'error': 'Queue not found'}), 404
        test_message = {
            'action': 'enable',
            'timestamp': datetime.now().isoformat(),
            'message': 'Queue enabled via dashboard'
        }
        sqs.send_message(QueueUrl=qurl, MessageBody=json.dumps(test_message))
        return jsonify({'queueName': queueName, 'enabled': True, 'message': 'Queue enabled successfully'})
    except Exception as e:
        print(f"Error enabling SQS queue: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<appName>/sqs/<queueName>/disable', methods=['POST'])
def disable_queue(appName: str, queueName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        sqs = baseSession.client('sqs')
        qurl = _find_queue_url(sqs, queueName)
        if not qurl:
            return jsonify({'error': 'Queue not found'}), 404
        sqs.purge_queue(QueueUrl=qurl)
        return jsonify({'queueName': queueName, 'enabled': False, 'message': 'Queue disabled (all messages purged)'})
    except Exception as e:
        print(f"Error disabling SQS queue: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<appName>/lambda/<functionName>/enable-concurrency', methods=['POST'])
def enable_provisioned_concurrency(appName: str, functionName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    data = request.json or {}
    concurrent = int(data.get('concurrentExecutions', 1))
    try:
        lam = baseSession.client('lambda')
        version = _get_latest_lambda_version(lam, functionName)
        if not version:
            return jsonify({'error': 'No published version found for this function'}), 400
        lam.put_provisioned_concurrency_config(FunctionName=functionName, Qualifier=version, ProvisionedConcurrentExecutions=concurrent)
        return jsonify({'success': True, 'application': appName, 'functionName': functionName, 'version': version, 'provisionedConcurrentExecutions': concurrent, 'status': 'enabled', 'lastModified': datetime.now().isoformat()})
    except Exception as e:
        print(f"Error enabling provisioned concurrency: {e}")
        return jsonify({'error': 'Failed to enable provisioned concurrency', 'details': str(e)}), 500

@app.route('/api/services/<appName>/lambda/<functionName>/disable-concurrency', methods=['POST'])
def disable_provisioned_concurrency(appName: str, functionName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        lam = baseSession.client('lambda')
        version = _get_latest_lambda_version(lam, functionName)
        if not version:
            return jsonify({'error': 'No published version found for this function'}), 400
        lam.delete_provisioned_concurrency_config(FunctionName=functionName, Qualifier=version)
        return jsonify({'success': True, 'application': appName, 'functionName': functionName, 'version': version, 'status': 'disabled', 'lastModified': datetime.now().isoformat()})
    except Exception as e:
        print(f"Error disabling provisioned concurrency: {e}")
        return jsonify({'error': 'Failed to disable provisioned concurrency', 'details': str(e)}), 500

@app.route('/api/services/<appName>/lambda/<functionName>/concurrency-status', methods=['GET'])
def get_provisioned_concurrency_status(appName: str, functionName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        lam = baseSession.client('lambda')
        version = _get_latest_lambda_version(lam, functionName)
        if not version:
            return jsonify({'application': appName, 'functionName': functionName, 'result': {'status': 'no_published_version', 'message': 'No published version found'}})
        try:
            resp = lam.get_provisioned_concurrency_config(FunctionName=functionName, Qualifier=version)
            pce = resp.get('ProvisionedConcurrencyConfig', {}).get('ProvisionedConcurrentExecutions', 0)
            return jsonify({'application': appName, 'functionName': functionName, 'result': {'status': 'enabled', 'version': version, 'provisionedConcurrentExecutions': pce, 'lastModified': datetime.now().isoformat()}})
        except Exception as inner:
            if 'ResourceNotFoundException' in str(inner):
                return jsonify({'application': appName, 'functionName': functionName, 'result': {'status': 'disabled', 'message': 'No provisioned concurrency configured'}})
            raise
    except Exception as e:
        print(f"Error getting provisioned concurrency status: {e}")
        return jsonify({'error': 'Failed to get provisioned concurrency status', 'details': str(e)}), 500

# -----------------------------
# Direct action APIs for native tabs (EC2/Lambda/SQS)
# -----------------------------

@app.route('/api/ec2/start', methods=['POST'])
def ec2_start_instances():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    data = request.json or {}
    instance_id = data.get('instanceId') or data.get('resourceId')
    if not instance_id:
        return jsonify({'error': 'instanceId is required'}), 400
    try:
        ec2 = baseSession.client('ec2')
        resp = ec2.start_instances(InstanceIds=[instance_id])
        return jsonify({'success': True, 'result': resp.get('StartingInstances', [])})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ec2/stop', methods=['POST'])
def ec2_stop_instances():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    data = request.json or {}
    instance_id = data.get('instanceId') or data.get('resourceId')
    if not instance_id:
        return jsonify({'error': 'instanceId is required'}), 400
    try:
        ec2 = baseSession.client('ec2')
        resp = ec2.stop_instances(InstanceIds=[instance_id])
        return jsonify({'success': True, 'result': resp.get('StoppingInstances', [])})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lambda/<functionName>/enable-concurrency', methods=['POST'])
def lambda_enable_concurrency(functionName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    data = request.json or {}
    concurrent = int(data.get('concurrentExecutions', 1))
    try:
        lam = baseSession.client('lambda')
        version = _get_latest_lambda_version(lam, functionName)
        if not version:
            return jsonify({'error': 'No published version found for this function'}), 400
        lam.put_provisioned_concurrency_config(FunctionName=functionName, Qualifier=version, ProvisionedConcurrentExecutions=concurrent)
        return jsonify({'success': True, 'functionName': functionName, 'version': version, 'provisionedConcurrentExecutions': concurrent})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lambda/<functionName>/disable-concurrency', methods=['POST'])
def lambda_disable_concurrency(functionName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        lam = baseSession.client('lambda')
        version = _get_latest_lambda_version(lam, functionName)
        if not version:
            return jsonify({'error': 'No published version found for this function'}), 400
        lam.delete_provisioned_concurrency_config(FunctionName=functionName, Qualifier=version)
        return jsonify({'success': True, 'functionName': functionName, 'version': version})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lambda/<functionName>/concurrency-status', methods=['GET'])
def lambda_concurrency_status(functionName: str):
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        lam = baseSession.client('lambda')
        # Use list API to find ANY provisioned concurrency config for this function
        # This avoids false "disabled" when a different version has the config
        try:
            listed = lam.list_provisioned_concurrency_configs(FunctionName=functionName)
            configs = listed.get('ProvisionedConcurrencyConfigs', []) or []
            if not configs:
                # Fall back to latest version check to provide friendly info
                version = _get_latest_lambda_version(lam, functionName)
                if not version:
                    return jsonify({'status': 'no_published_version'})
                try:
                    resp = lam.get_provisioned_concurrency_config(FunctionName=functionName, Qualifier=version)
                    config = resp.get('ProvisionedConcurrencyConfig', {})
                    status = (config.get('Status') or 'UNKNOWN')
                    pce = config.get('ProvisionedConcurrentExecutions', 0)
                    requested_pce = (config.get('RequestedConfiguration', {}) or {}).get('ProvisionedConcurrentExecutions', 0)
                    actual_pce = pce if (status or '').upper() == 'READY' else requested_pce
                    is_enabled = (status or '').upper() not in ['DISABLED', 'FAILED', 'UNKNOWN'] and (requested_pce or pce) > 0
                    return jsonify({
                        'status': 'enabled' if is_enabled else 'disabled',
                        'version': version,
                        'provisionedConcurrentExecutions': actual_pce,
                        'aws_status': status
                    })
                except Exception as inner2:
                    msg2 = str(inner2)
                    if 'ResourceNotFoundException' in msg2:
                        return jsonify({'status': 'disabled'})
                    if 'AccessDenied' in msg2 or 'UnrecognizedClient' in msg2 or 'InvalidClientTokenId' in msg2:
                        return jsonify({'status': 'unknown', 'message': 'AWS credentials or permissions issue'})
                    return jsonify({'status': 'unknown', 'message': msg2}), 200

            # Choose the config with the most recent LastModified or highest requested
            best = max(
                configs,
                key=lambda c: (
                    (c.get('LastModified') or ''),
                    (c.get('RequestedProvisionedConcurrentExecutions') or 0)
                )
            )
            status = (best.get('Status') or 'UNKNOWN')
            requested = best.get('RequestedProvisionedConcurrentExecutions') or 0
            allocated = best.get('AllocatedProvisionedConcurrentExecutions') or 0
            qualifier = best.get('Qualifier')
            actual_pce = allocated if (status or '').upper() == 'READY' else requested
            is_enabled = (status or '').upper() not in ['DISABLED', 'FAILED', 'UNKNOWN'] and (requested or allocated) > 0
            return jsonify({
                'status': 'enabled' if is_enabled else 'disabled',
                'qualifier': qualifier,
                'provisionedConcurrentExecutions': actual_pce,
                'aws_status': status,
                'requested': requested,
                'allocated': allocated
            })
        except Exception as inner:
            msg = str(inner)
            if 'AccessDenied' in msg or 'UnrecognizedClient' in msg or 'InvalidClientTokenId' in msg:
                return jsonify({'status': 'unknown', 'message': 'AWS credentials or permissions issue'})
            return jsonify({'status': 'unknown', 'message': msg}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lambda/invoke', methods=['POST'])
def lambda_invoke():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    data = request.json or {}
    function_name = data.get('functionName')
    payload = data.get('payload', {})
    if not function_name:
        return jsonify({'error': 'functionName is required'}), 400
    try:
        lam = baseSession.client('lambda')
        resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode('utf-8'))
        raw = resp.get('Payload').read() if resp.get('Payload') else b''
        body = None
        try:
            body = json.loads(raw.decode('utf-8')) if raw else None
        except Exception:
            body = raw.decode('utf-8') if raw else None
        return jsonify({'statusCode': resp.get('StatusCode'), 'functionError': resp.get('FunctionError'), 'payload': body})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sqs', methods=['GET'])
def list_sqs():
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        prefix = request.args.get('prefix')
        sqs = baseSession.client('sqs')
        kwargs = {'QueueNamePrefix': prefix} if prefix else {}
        resp = sqs.list_queues(**kwargs)
        names = []
        for url in resp.get('QueueUrls', []) or []:
            names.append(url.rsplit('/', 1)[-1])
        return jsonify({'queues': names})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ----------------------------------------
# VPC Flow Logs based SSH activity summary
# ----------------------------------------

@app.route('/api/ec2/ssh-activity', methods=['GET'])
def ec2_ssh_activity():
    """Summarize SSH (port 22) connections per EC2 instance using VPC Flow Logs.

    Query params (optional):
      - hours: lookback window, default 24
      - logGroup: CloudWatch Logs group name for VPC Flow Logs. If omitted, uses env FLOW_LOGS_LOG_GROUP
      - limit: max source breakdown entries per instance, default 10
    """
    ensure_session()
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401

    try:
        hours = int(request.args.get('hours', '24'))
        limit = int(request.args.get('limit', '10'))
        log_group = request.args.get('logGroup') or os.environ.get('FLOW_LOGS_LOG_GROUP')
        logs = baseSession.client('logs')
        # If not provided, try to auto-discover a VPC Flow Logs group
        if not log_group:
            try:
                paginator = logs.get_paginator('describe_log_groups')
                latest = None
                for page in paginator.paginate(logGroupNamePrefix='/aws/vpc/flow-logs'):
                    for g in page.get('logGroups', []) or []:
                        # pick the most recently created group
                        if (latest is None) or (g.get('creationTime', 0) > latest.get('creationTime', 0)):
                            latest = g
                if latest and latest.get('logGroupName'):
                    log_group = latest['logGroupName']
                else:
                    return jsonify({'items': [], 'windowHours': hours, 'note': 'No VPC Flow Logs log group found. Set FLOW_LOGS_LOG_GROUP env or enable VPC Flow Logs.'}), 200
            except Exception as e:
                return jsonify({'items': [], 'windowHours': hours, 'note': f'Could not list log groups: {str(e)}'}), 200

        end_ts = int(time.time())
        start_ts = end_ts - hours * 3600

        # Query per (eni, srcAddr) hit counts for TCP:22 ACCEPT
        query_string = (
            "fields interfaceId, srcAddr, dstPort, protocol, action\n"
            "| filter action = 'ACCEPT' and dstPort = 22 and protocol = 6\n"
            "| stats count() as hits by interfaceId, srcAddr\n"
            "| sort hits desc\n"
            "| limit 50000"
        )

        try:
            start = logs.start_query(
                logGroupName=log_group,
                startTime=start_ts,
                endTime=end_ts,
                queryString=query_string
            )
        except Exception as e:
            return jsonify({'items': [], 'windowHours': hours, 'logGroup': log_group, 'note': f'Failed to start Logs Insights query: {str(e)}'}), 200
        query_id = start.get('queryId')

        # Poll for results
        status = 'Running'
        results = []
        for _ in range(30):
            time.sleep(1.0)
            resp = logs.get_query_results(queryId=query_id)
            status = resp.get('status')
            if status in ('Complete', 'Failed', 'Cancelled', 'Timeout'):
                results = resp.get('results', [])
                break
        if status != 'Complete':
            return jsonify({'items': [], 'windowHours': hours, 'logGroup': log_group, 'note': f'Logs Insights query {status}'}), 200

        # Convert results to dictionaries
        def as_dict(row):
            return {kv['field']: kv['value'] for kv in row}

        eni_to_sources = {}
        for row in results:
            item = as_dict(row)
            eni = item.get('interfaceId')
            src = item.get('srcAddr')
            hits = int(item.get('hits', '0')) if item.get('hits') is not None else 0
            if not eni or not src:
                continue
            lst = eni_to_sources.setdefault(eni, [])
            lst.append({'ip': src, 'hits': hits})

        if not eni_to_sources:
            return jsonify({'items': [], 'windowHours': hours})

        # Map ENI -> InstanceId
        ec2 = baseSession.client('ec2')
        eni_ids = list(eni_to_sources.keys())
        eni_to_instance = {}
        # Describe in chunks of 100
        try:
            for i in range(0, len(eni_ids), 100):
                batch = eni_ids[i:i+100]
                if not batch:
                    continue
                desc = ec2.describe_network_interfaces(NetworkInterfaceIds=batch)
                for ni in desc.get('NetworkInterfaces', []) or []:
                    att = ni.get('Attachment') or {}
                    inst_id = att.get('InstanceId')
                    eni_to_instance[ni.get('NetworkInterfaceId')] = inst_id
        except Exception as e:
            # Fall back to showing ENI-based results if Describe is not permitted
            items = []
            for eni, sources in eni_to_sources.items():
                total = sum(s['hits'] for s in sources)
                merged = {}
                for s in sources:
                    merged[s['ip']] = merged.get(s['ip'], 0) + s['hits']
                top = [{'ip': ip, 'hits': hits} for ip, hits in merged.items()]
                top.sort(key=lambda x: x['hits'], reverse=True)
                items.append({'instanceId': f'eni:{eni}', 'totalConnections': total, 'uniqueSourceIps': len(merged), 'topSources': top[:limit]})
            items.sort(key=lambda x: x['totalConnections'], reverse=True)
            return jsonify({'items': items, 'windowHours': hours, 'logGroup': log_group, 'note': f'Partial results (no DescribeNetworkInterfaces): {str(e)}'}), 200

        # Aggregate per instance
        per_instance = {}
        for eni, sources in eni_to_sources.items():
            inst_id = eni_to_instance.get(eni) or f"eni:{eni}"
            acc = per_instance.setdefault(inst_id, {'totalConnections': 0, 'uniqueSourceIps': 0, 'topSources': []})
            acc['totalConnections'] += sum(s['hits'] for s in sources)
            # Merge sources by IP
            ip_to_hits = {s['ip']: s['hits'] for s in acc['topSources']}
            for s in sources:
                ip_to_hits[s['ip']] = ip_to_hits.get(s['ip'], 0) + s['hits']
            # Rebuild sorted top list
            merged = [{'ip': ip, 'hits': hits} for ip, hits in ip_to_hits.items()]
            merged.sort(key=lambda x: x['hits'], reverse=True)
            acc['topSources'] = merged[:limit]
            acc['uniqueSourceIps'] = len(ip_to_hits)

        # Format items
        items = []
        for inst_id, data in per_instance.items():
            items.append({
                'instanceId': inst_id,
                **data
            })
        # Sort by total connections desc
        items.sort(key=lambda x: x['totalConnections'], reverse=True)

        return jsonify({'items': items, 'windowHours': hours})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sqs/details', methods=['GET'])
def list_sqs_with_attributes():
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        prefix = request.args.get('prefix')
        sqs = baseSession.client('sqs')
        kwargs = {'QueueNamePrefix': prefix} if prefix else {}
        resp = sqs.list_queues(**kwargs)
        urls = resp.get('QueueUrls', []) or []
        results = []

        # Fetch attributes in parallel for faster response
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def fetch_attrs(qurl: str):
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=qurl,
                    AttributeNames=[
                        'ApproximateNumberOfMessages',
                        'ApproximateNumberOfMessagesNotVisible',
                        'ApproximateNumberOfMessagesDelayed',
                        'CreatedTimestamp',
                        'LastModifiedTimestamp'
                    ]
                )['Attributes']
            except Exception as err:
                attrs = {'error': str(err)}
            name = qurl.rsplit('/', 1)[-1]
            return {'name': name, 'attributes': attrs}

        with ThreadPoolExecutor(max_workers=min(16, max(4, len(urls)))) as ex:
            futures = [ex.submit(fetch_attrs, u) for u in urls]
            for fut in as_completed(futures):
                results.append(fut.result())

        return jsonify({'queues': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sqs/status/<queueName>', methods=['GET'])
def sqs_status(queueName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        sqs = baseSession.client('sqs')
        qurl = _find_queue_url(sqs, queueName)
        if not qurl:
            return jsonify({'error': 'Queue not found'}), 404
        attrs = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=['ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible', 'ApproximateNumberOfMessagesDelayed', 'CreatedTimestamp', 'LastModifiedTimestamp'])['Attributes']
        return jsonify({'queueName': queueName, **attrs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sqs/enable/<queueName>', methods=['POST'])
def sqs_enable(queueName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        sqs = baseSession.client('sqs')
        qurl = _find_queue_url(sqs, queueName)
        if not qurl:
            return jsonify({'error': 'Queue not found'}), 404
        sqs.send_message(QueueUrl=qurl, MessageBody=json.dumps({'action': 'enable', 'timestamp': datetime.now().isoformat()}))
        return jsonify({'queueName': queueName, 'enabled': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sqs/disable/<queueName>', methods=['POST'])
def sqs_disable(queueName: str):
    if not baseSession:
        return jsonify({'error': 'Not connected to AWS'}), 401
    try:
        sqs = baseSession.client('sqs')
        qurl = _find_queue_url(sqs, queueName)
        if not qurl:
            return jsonify({'error': 'Queue not found'}), 404
        sqs.purge_queue(QueueUrl=qurl)
        return jsonify({'queueName': queueName, 'enabled': False})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)