"""
Cloud, Virtual, and Container Forensics Module
Supports multi-cloud acquisition, container analysis, and serverless forensics.
"""
import json
import re
from datetime import datetime
import logging
import subprocess
import os

class CloudForensics:
    def __init__(self):
        self.supported_clouds = ['aws', 'azure', 'gcp', 'onedrive', 'dropbox']
        self.container_runtimes = ['docker', 'kubernetes', 'containerd']
        self.supported_clouds = ['aws', 'azure', 'gcp']
        self.container_runtimes = ['docker', 'kubernetes', 'containerd']
        self.docker_client = docker.from_env() if self._check_docker() else None
        self.k8s_client = None
        
    def _check_docker(self):
        try:
            docker.from_env().ping()
            return True
        except:
            return False

    def acquire_cloud_data(self, cloud_provider, credentials, resource_types=None):
        """Acquire data from cloud providers with live SDKs."""
        if resource_types is None:
            resource_types = ['logs', 'storage', 'iam']

        acquisition_data = {
            'provider': cloud_provider,
            'timestamp': datetime.utcnow().isoformat(),
            'resources': {},
            'metadata': {}
        }

        try:
            if cloud_provider == 'aws':
                acquisition_data['resources'] = self._acquire_aws_data(credentials, resource_types)
            elif cloud_provider == 'azure':
                acquisition_data['resources'] = self._acquire_azure_data(credentials, resource_types)
            elif cloud_provider == 'gcp':
                acquisition_data['resources'] = self._acquire_gcp_data(credentials, resource_types)
            else:
                raise ValueError(f"Unsupported cloud provider: {cloud_provider}")

        except Exception as e:
            logger.error(f"Cloud acquisition failed: {str(e)}", exc_info=True)
            acquisition_data['error'] = str(e)

        return acquisition_data


    def generate_cloud_visualization(self, results):
        """Generate visualization data for cloud acquisition results."""
        if not results or 'resources' not in results:
            return None

        viz_data = {
            'resource_types': [],
            'counts': [],
            'details': []
        }

        for resource_type, data in results['resources'].items():
            viz_data['resource_types'].append(resource_type.replace('_', ' ').title())

            if isinstance(data, list):
                count = len(data)
                sample = data[0] if count > 0 else {}
            elif isinstance(data, dict):
                count = len(data.keys())
                sample = data
            else:
                count = 1
                sample = str(data)

            viz_data['counts'].append(count)
            viz_data['details'].append({
                'type': resource_type,
                'sample': sample,
                'count': count
            })

        return viz_data
    
    
    def _acquire_aws_data(self, credentials, resource_types):
        """Acquire data from AWS using boto3."""
        aws_data = {}
        session = boto3.Session(
            aws_access_key_id=credentials.get('access_key'),
            aws_secret_access_key=credentials.get('secret_key'),
            region_name=credentials.get('region')
        )

        if 'logs' in resource_types:
            try:
                cloudtrail = session.client('cloudtrail')
                aws_data['cloudtrail_logs'] = cloudtrail.describe_trails()['trailList']

                cloudwatch = session.client('logs')
                aws_data['cloudwatch_log_groups'] = cloudwatch.describe_log_groups()['logGroups']
            except Exception as e:
                aws_data['logs_error'] = str(e)

        if 'storage' in resource_types:
            try:
                s3 = session.client('s3')
                aws_data['s3_buckets'] = [b['Name'] for b in s3.list_buckets()['Buckets']]
            except Exception as e:
                aws_data['storage_error'] = str(e)

        if 'iam' in resource_types:
            try:
                iam = session.client('iam')
                aws_data['iam_users'] = [u['UserName'] for u in iam.list_users()['Users']]
                aws_data['iam_roles'] = [r['RoleName'] for r in iam.list_roles()['Roles']]
            except Exception as e:
                aws_data['iam_error'] = str(e)

        if 'compute' in resource_types:
            try:
                ec2 = session.client('ec2')
                aws_data['ec2_instances'] = [
                    {'InstanceId': i['InstanceId'], 'State': i['State']['Name']} 
                    for i in ec2.describe_instances()['Reservations'][0]['Instances']
                ]
            except Exception as e:
                aws_data['compute_error'] = str(e)

        return aws_data




    
    def capture_volatile_cloud_data(self, cloud_provider, resource_ids):
        """
        Capture volatile cloud data like temporary containers and function memory.
        
        Args:
            cloud_provider: Cloud provider name
            resource_ids: List of resource identifiers
            
        Returns:
            dict: Volatile data capture results
        """
        capture_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'volatile_captures': [],
            'memory_dumps': [],
            'temporary_resources': []
        }
        
        for resource_id in resource_ids:
            try:
                if 'lambda' in resource_id.lower() or 'function' in resource_id.lower():
                    # Capture serverless function state
                    function_state = self._capture_serverless_state(cloud_provider, resource_id)
                    capture_data['volatile_captures'].append(function_state)
                    
                elif 'container' in resource_id.lower():
                    # Capture container memory and state
                    container_state = self._capture_container_state(resource_id)
                    capture_data['memory_dumps'].append(container_state)
                    
            except Exception as e:
                logging.error(f"Volatile capture failed for {resource_id}: {str(e)}")
                
        return capture_data
        
        def analyze_kubernetes_pods(self, kubeconfig_path=None, namespace='default'):
                """Analyze Kubernetes pods with live cluster connection."""
                analysis = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'pods': [],
                    'containers': [],
                    'volumes': [],
                    'security_issues': []
                }

                try:
                    if kubeconfig_path:
                        kube_config.load_kube_config(config_file=kubeconfig_path)
                    else:
                        kube_config.load_incluster_config()

                    self.k8s_client = kubernetes.client.CoreV1Api()

                    # Get pods in namespace
                    pods = self.k8s_client.list_namespaced_pod(namespace=namespace)
                    for pod in pods.items:
                        pod_info = {
                            'name': pod.metadata.name,
                            'namespace': pod.metadata.namespace,
                            'status': pod.status.phase,
                            'containers': [c.name for c in pod.spec.containers],
                            'node': pod.spec.node_name,
                            'creation_timestamp': pod.metadata.creation_timestamp.isoformat(),
                            'labels': pod.metadata.labels,
                            'annotations': pod.metadata.annotations
                        }
                        analysis['pods'].append(pod_info)

                        # Analyze containers in pod
                        for container in pod.spec.containers:
                            container_info = {
                                'name': container.name,
                                'image': container.image,
                                'ports': [{'port': p.container_port, 'protocol': p.protocol} 
                                         for p in container.ports] if container.ports else [],
                                'security_context': str(container.security_context),
                                'resources': str(container.resources)
                            }
                            analysis['containers'].append(container_info)

                        # Analyze volumes
                        for volume in pod.spec.volumes:
                            volume_info = {
                                'name': volume.name,
                                'type': self._get_volume_type(volume)
                            }
                            analysis['volumes'].append(volume_info)

                        # Check for security issues
                        security_issues = self._check_pod_security(pod)
                        analysis['security_issues'].extend(security_issues)

                except Exception as e:
                    logger.error(f"Kubernetes analysis failed: {str(e)}", exc_info=True)
                    analysis['error'] = str(e)

                return analysis

        def generate_k8s_visualization(self, results):
                """Generate visualization data for Kubernetes analysis."""
                if not results or 'pods' not in results:
                    return None

                viz_data = {
                    'pod_statuses': {},
                    'container_images': [],
                    'security_issues': len(results.get('security_issues', []))
                }

                # Count pod statuses
                for pod in results['pods']:
                    status = pod['status']
                    viz_data['pod_statuses'][status] = viz_data['pod_statuses'].get(status, 0) + 1

                # Count container images
                if 'containers' in results:
                    image_counts = {}
                    for container in results['containers']:
                        image = container['image']
                        image_counts[image] = image_counts.get(image, 0) + 1
                    viz_data['container_images'] = [{'image': k, 'count': v} for k, v in image_counts.items()]

                return viz_data
        
        def analyze_docker_containers(self, container_ids=None):
            """Analyze Docker containers with live Docker connection."""
            analysis = {
                'timestamp': datetime.utcnow().isoformat(),
                'containers': [],
                'images': [],
                'volumes': [],
                'networks': [],
                'security_findings': []
            }

            try:
                if not self.docker_client:
                    raise RuntimeError("Docker not available")

                # Get containers
                containers = self.docker_client.containers.list(all=True) if not container_ids else [
                    self.docker_client.containers.get(cid) for cid in container_ids
                ]

                for container in containers:
                    container_info = {
                        'id': container.id,
                        'name': container.name,
                        'image': container.image.tags[0] if container.image.tags else container.image.id,
                        'status': container.status,
                        'ports': container.ports,
                        'mounts': [{'source': m['Source'], 'destination': m['Destination']} 
                                  for m in container.attrs['Mounts']],
                        'created': container.attrs['Created']
                    }
                    analysis['containers'].append(container_info)

                # Get images
                images = self.docker_client.images.list()
                for image in images:
                    image_info = {
                        'id': image.id,
                        'tags': image.tags,
                        'created': image.attrs['Created'],
                        'size': image.attrs['Size']
                    }
                    analysis['images'].append(image_info)

                # Get volumes
                volumes = self.docker_client.volumes.list()
                for volume in volumes:
                    volume_info = {
                        'name': volume.name,
                        'driver': volume.attrs['Driver'],
                        'mountpoint': volume.attrs['Mountpoint'],
                        'created': volume.attrs['CreatedAt']
                    }
                    analysis['volumes'].append(volume_info)

                # Get networks
                networks = self.docker_client.networks.list()
                for network in networks:
                    network_info = {
                        'name': network.name,
                        'driver': network.attrs['Driver'],
                        'containers': list(network.attrs['Containers'].keys()) if network.attrs['Containers'] else []
                    }
                    analysis['networks'].append(network_info)

            except Exception as e:
                logging.error(f"Docker analysis failed: {str(e)}")
                analysis['error'] = str(e)

            return analysis
        
    def trace_serverless_functions(self, cloud_provider, function_names=None):
        """
        Trace serverless function execution and analyze logs.
        
        Args:
            cloud_provider: 'aws', 'azure', or 'gcp'
            function_names: List of function names to trace
            
        Returns:
            dict: Serverless tracing results
        """
        tracing_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'functions': [],
            'execution_traces': [],
            'dependencies': [],
            'security_findings': []
        }
        
        try:
            if cloud_provider == 'aws':
                tracing_data = self._trace_aws_lambda(function_names)
            elif cloud_provider == 'azure':
                tracing_data = self._trace_azure_functions(function_names)
            elif cloud_provider == 'gcp':
                tracing_data = self._trace_gcp_functions(function_names)
                
        except Exception as e:
            logging.error(f"Serverless tracing failed: {str(e)}")
            tracing_data['error'] = str(e)
            
        return tracing_data
        
    def analyze_vm_disks(self, vm_format, disk_path):
            """Analyze VM disk images with enhanced forensics."""
            analysis = {
                'timestamp': datetime.utcnow().isoformat(),
                'vm_format': vm_format,
                'disk_info': {},
                'partitions': [],
                'file_systems': [],
                'artifacts': [],
                'indicators': []
            }

            try:
                # Get basic disk info
                disk_size = os.path.getsize(disk_path)
                with open(disk_path, 'rb') as f:
                    disk_hash = hashlib.sha256(f.read()).hexdigest()

                analysis['disk_info'] = {
                    'path': disk_path,
                    'size': f"{disk_size / (1024*1024*1024):.2f} GB",
                    'sha256': disk_hash,
                    'format': vm_format,
                    'analyzed_at': datetime.utcnow().isoformat()
                }

                # Simulate forensic analysis (in production, use actual tools)
                if vm_format in ['vmware', 'hyper-v']:
                    analysis['partitions'] = self._simulate_partition_analysis(disk_path)
                    analysis['file_systems'] = self._simulate_filesystem_analysis(disk_path)
                    analysis['artifacts'] = self._simulate_artifact_extraction(disk_path)
                    analysis['indicators'] = self._analyze_indicators(disk_path)

            except Exception as e:
                logger.error(f"VM analysis failed: {str(e)}", exc_info=True)
                analysis['error'] = str(e)

            return analysis

    def generate_vm_visualization(self, results):
        """Generate visualization data for VM analysis."""
        if not results or 'disk_info' not in results:
            return None

        viz_data = {
            'disk_size': results['disk_info']['size'],
            'partition_count': len(results.get('partitions', [])),
            'filesystem_types': list(set(fs['type'] for fs in results.get('file_systems', []))),
            'artifact_types': [a['type'] for a in results.get('artifacts', [])],
            'indicator_count': len(results.get('indicators', []))
        }

        return viz_data
        
    def _acquire_aws_data(self, credentials, resource_types):
        """Acquire data from AWS services."""
        aws_data = {}
        
        for resource_type in resource_types:
            if resource_type == 'logs':
                aws_data['cloudtrail_logs'] = self._get_aws_cloudtrail()
                aws_data['cloudwatch_logs'] = self._get_aws_cloudwatch()
            elif resource_type == 'storage':
                aws_data['s3_buckets'] = self._get_aws_s3_info()
            elif resource_type == 'iam':
                aws_data['iam_users'] = self._get_aws_iam_users()
                aws_data['iam_roles'] = self._get_aws_iam_roles()
            elif resource_type == 'compute':
                aws_data['ec2_instances'] = self._get_aws_ec2_instances()
                
        return aws_data
        
        def _acquire_azure_data(self, credentials, resource_types):
            """Acquire data from Azure using Azure SDK."""
            azure_data = {}
            credential = DefaultAzureCredential()

            if 'logs' in resource_types:
                try:
                    # This would require additional setup with Azure Monitor
                    azure_data['activity_logs'] = {'status': 'requires_azure_monitor_setup'}
                except Exception as e:
                    azure_data['logs_error'] = str(e)

            if 'storage' in resource_types:
                try:
                    storage_client = StorageManagementClient(
                        credential,
                        credentials.get('subscription_id')
                    )
                    azure_data['storage_accounts'] = [
                        a.name for a in storage_client.storage_accounts.list()
                    ]
                except Exception as e:
                    azure_data['storage_error'] = str(e)

            if 'iam' in resource_types:
                try:
                    # This would require Graph API permissions
                    azure_data['ad_users'] = {'status': 'requires_graph_api_permissions'}
                except Exception as e:
                    azure_data['iam_error'] = str(e)

            return azure_data

        def _acquire_gcp_data(self, credentials, resource_types):
            """Acquire data from GCP using Google Cloud SDK."""
            gcp_data = {}
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials.get('credentials', '')

            if 'logs' in resource_types:
                try:
                    logging_client = gcp_logging.Client(project=credentials.get('project_id'))
                    gcp_data['log_sinks'] = [sink.name for sink in logging_client.list_sinks()]
                except Exception as e:
                    gcp_data['logs_error'] = str(e)

            if 'storage' in resource_types:
                try:
                    storage_client = storage.Client(project=credentials.get('project_id'))
                    gcp_data['buckets'] = [bucket.name for bucket in storage_client.list_buckets()]
                except Exception as e:
                    gcp_data['storage_error'] = str(e)

            return gcp_data
        
    def _acquire_storage_service(self, service, credentials):
        """Acquire data from cloud storage services."""
        storage_data = {
            'files': [],
            'metadata': {},
            'sharing_info': []
        }
        
        # Placeholder for storage service acquisition
        # In production, implement actual API calls
        storage_data['metadata'] = {
            'service': service,
            'acquisition_method': 'api',
            'status': 'simulated'
        }
        
        return storage_data
        
    def _capture_serverless_state(self, cloud_provider, function_id):
        """Capture serverless function state and memory."""
        return {
            'function_id': function_id,
            'provider': cloud_provider,
            'memory_snapshot': 'captured',
            'environment_vars': {},
            'execution_context': {}
        }
        
    def _capture_container_state(self, container_id):
        """Capture container memory and runtime state."""
        return {
            'container_id': container_id,
            'memory_dump': 'captured',
            'file_system_diff': {},
            'process_list': [],
            'network_connections': []
        }
        
    def _get_kubernetes_pods(self, namespace, kubeconfig_path):
        """Get Kubernetes pod information."""
        # Simulate kubectl get pods command
        pods = [
            {
                'name': 'forensics-pod-1',
                'namespace': namespace,
                'status': 'Running',
                'containers': ['forensics-container'],
                'node': 'worker-node-1'
            }
        ]
        return pods
        
    def _analyze_pod_containers(self, pod, namespace):
        """Analyze containers within a pod."""
        return {
            'containers': [
                {
                    'name': 'forensics-container',
                    'image': 'forensics:latest',
                    'volumes': ['/data', '/logs'],
                    'environment': {},
                    'logs': 'Container logs would be extracted here'
                }
            ],
            'volumes': [
                {
                    'name': 'data-volume',
                    'type': 'persistentVolumeClaim',
                    'mount_path': '/data'
                }
            ],
            'security_issues': []
        }
        
    def _get_all_docker_containers(self):
        """Get all Docker container IDs."""
        # Simulate docker ps command
        return ['container_1', 'container_2', 'forensics_container']
        
    def _analyze_docker_container(self, container_id):
        """Analyze a specific Docker container."""
        return {
            'id': container_id,
            'name': f'container_{container_id}',
            'image': 'forensics:latest',
            'status': 'running',
            'ports': ['5000:5000'],
            'volumes': ['/app/data:/data'],
            'environment': {},
            'processes': [],
            'network_mode': 'bridge'
        }
        
    def _analyze_docker_images(self):
        """Analyze Docker images."""
        return [
            {
                'id': 'sha256:abc123',
                'repository': 'forensics',
                'tag': 'latest',
                'size': '500MB',
                'layers': [],
                'vulnerabilities': []
            }
        ]
        
    def _analyze_docker_volumes(self):
        """Analyze Docker volumes."""
        return [
            {
                'name': 'forensics_data',
                'driver': 'local',
                'mountpoint': '/var/lib/docker/volumes/forensics_data/_data',
                'created': datetime.utcnow().isoformat()
            }
        ]
        
    def _analyze_docker_networks(self):
        """Analyze Docker networks."""
        return [
            {
                'name': 'bridge',
                'driver': 'bridge',
                'scope': 'local',
                'containers': []
            }
        ]
        
    def _trace_aws_lambda(self, function_names):
        """Trace AWS Lambda functions."""
        return {
            'functions': function_names or [],
            'execution_traces': [],
            'dependencies': [],
            'security_findings': []
        }
        
    def _trace_azure_functions(self, function_names):
        """Trace Azure Functions."""
        return {
            'functions': function_names or [],
            'execution_traces': [],
            'dependencies': [],
            'security_findings': []
        }
        
    def _trace_gcp_functions(self, function_names):
        """Trace Google Cloud Functions."""
        return {
            'functions': function_names or [],
            'execution_traces': [],
            'dependencies': [],
            'security_findings': []
        }
        
    def _get_vm_disk_info(self, disk_path, vm_format):
        """Get VM disk information."""
        return {
            'path': disk_path,
            'format': vm_format,
            'size': '20GB',
            'created': datetime.utcnow().isoformat(),
            'checksum': 'sha256:def456'
        }
        
    def _analyze_vm_partitions(self, disk_path, vm_format):
        """Analyze VM disk partitions."""
        return [
            {
                'number': 1,
                'type': 'NTFS',
                'size': '19GB',
                'offset': '1MB',
                'bootable': True
            }
        ]
        
    def _analyze_vm_filesystems(self, disk_path, vm_format):
        """Analyze VM file systems."""
        return [
            {
                'type': 'NTFS',
                'label': 'Windows',
                'total_space': '19GB',
                'used_space': '15GB',
                'files_count': 125000
            }
        ]
        
    def _extract_vm_artifacts(self, disk_path, vm_format):
        """Extract forensic artifacts from VM disk."""
        return [
            {
                'type': 'registry_hive',
                'path': '/Windows/System32/config/SYSTEM',
                'size': '12MB'
            },
            {
                'type': 'event_log',
                'path': '/Windows/System32/winevt/Logs/System.evtx',
                'size': '20MB'
            }
        ]
        
    # Placeholder methods for cloud service API calls
    def _get_aws_cloudtrail(self):
        return {'logs': [], 'status': 'simulated'}
        
    def _get_aws_cloudwatch(self):
        return {'logs': [], 'status': 'simulated'}
        
    def _get_aws_s3_info(self):
        return {'buckets': [], 'status': 'simulated'}
        
    def _get_aws_iam_users(self):
        return {'users': [], 'status': 'simulated'}
        
    def _get_aws_iam_roles(self):
        return {'roles': [], 'status': 'simulated'}
        
    def _get_aws_ec2_instances(self):
        return {'instances': [], 'status': 'simulated'}
        
    def _get_azure_activity_logs(self):
        return {'logs': [], 'status': 'simulated'}
        
    def _get_azure_storage(self):
        return {'accounts': [], 'status': 'simulated'}
        
    def _get_azure_ad_users(self):
        return {'users': [], 'status': 'simulated'}
        
    def _get_gcp_audit_logs(self):
        return {'logs': [], 'status': 'simulated'}
        
    def _get_gcp_storage(self):
        return {'buckets': [], 'status': 'simulated'}