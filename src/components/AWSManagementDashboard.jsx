import React, { useState, useEffect } from 'react';
import { 
  Cloud, 
  Server, 
  Database, 
  Zap, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Activity,
  Settings,
  Key,
  Eye,
  Play,
  Pause,
  HardDrive,
  Globe,
  Lock,
  TrendingUp,
  AlertCircle,
  Cpu,
  MemoryStick,
  Users,
  Network,
  Folder,
  RefreshCw,
  ExternalLink,
  Clock,
  MapPin
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5001/api';

const AWSManagementDashboard = () => {
  const [credentials, setCredentials] = useState({ 
    accessKey: '', 
    secretKey: '', 
    region: 'ap-south-1' 
  });
  const [isConnected, setIsConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [awsData, setAwsData] = useState({
    ec2: [],
    rds: [],
    lambda: [],
    s3: [],
    vpc: [],
    subnets: [],
    iam_users: [],
    iam_roles: [],
    security_alerts: [],
    cloudwatch_metrics: {},
    cloudwatch_logs: {},
    cloudwatch_alarms: {}
  });
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

	// Controller state
	const [controllerApps, setControllerApps] = useState([]);
	const [controllerLoading, setControllerLoading] = useState(false);
	const [selectedApp, setSelectedApp] = useState('');
	const [selectedServiceType, setSelectedServiceType] = useState('ec2');
	const [controllerResources, setControllerResources] = useState([]);
	const [lambdaConcurrency, setLambdaConcurrency] = useState({});
	// UI action states for -ing/-ed feedback
	const [ec2ActionState, setEc2ActionState] = useState({}); // { [instanceId]: 'starting'|'started'|'stopping'|'stopped' }
	const [lambdaActionState, setLambdaActionState] = useState({}); // { [fn]: { invoke, enable, disable } }
	const [sqsActionState, setSqsActionState] = useState({}); // { [queue]: { status, enable, disable } }

  const fetchAllResources = async () => {
    try {
      setRefreshing(true);
      const response = await fetch(`${API_BASE_URL}/resources`);
      if (response.ok) {
        const data = await response.json();
        setAwsData(data);
      } else {
        console.error('Failed to fetch resources');
      }
    } catch (error) {
      console.error('Error fetching resources:', error);
    } finally {
      setRefreshing(false);
    }
  };

  const handleConnect = async () => {
    if (!credentials.accessKey || !credentials.secretKey) return;
    
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/connect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
      });
      
      if (response.ok) {
        setIsConnected(true);
        await fetchAllResources();
      } else {
        const error = await response.json();
        alert(`Connection failed: ${error.message}`);
      }
    } catch (error) {
      console.error('Connection error:', error);
      alert('Connection failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

	// -----------------------------
	// Service Controller functions
	// -----------------------------
  const fetchApplications = async () => {
		try {
			setControllerLoading(true);
			const res = await fetch(`${API_BASE_URL}/services`);
			if (res.ok) {
				const data = await res.json();
				setControllerApps(data.applications || []);
				if (!selectedApp && (data.applications || []).length > 0) {
					setSelectedApp(data.applications[0]);
				}
			} else {
				console.error('Failed to load applications');
			}
		} catch (e) {
			console.error('Error loading applications:', e);
		} finally {
			setControllerLoading(false);
		}
	};

  const fetchControllerStatus = async (_app = '', type = selectedServiceType) => {
    try {
      setControllerLoading(true);
      if (type === 'sqs') {
        const res = await fetch(`${API_BASE_URL}/sqs/details`);
        if (res.ok) {
          const data = await res.json();
          const details = (data.queues || []).map(q => ({ resourceId: q.name, attributes: q.attributes }));
          setControllerResources(details);
        } else {
          setControllerResources([]);
        }
      } else if (type === 'lambda') {
        // No list endpoint: use already loaded awsData.lambda names
        const resources = (awsData.lambda || []).map(f => ({ resourceId: f.name }));
        setControllerResources(resources);
        // populate concurrency map best-effort
        const entries = await Promise.all(resources.map(async r => {
          try {
            const s = await fetch(`${API_BASE_URL}/lambda/${encodeURIComponent(r.resourceId)}/concurrency-status`);
            if (s.ok) {
              const payload = await s.json();
              return [r.resourceId, payload || { status: 'unknown' }];
            }
          } catch {}
          return [r.resourceId, { status: 'unknown' }];
        }));
        const map = {};
        entries.forEach(([k, v]) => { map[k] = v; });
        setLambdaConcurrency(map);
      } else {
        setControllerResources([]);
      }
    } catch (e) {
      console.error('Error loading data:', e);
      setControllerResources([]);
    } finally {
      setControllerLoading(false);
    }
  };

  const startResource = async (resourceId) => {
		try {
			setControllerLoading(true);
			setEc2ActionState(prev => ({ ...prev, [resourceId]: 'starting' }));
			const url = `${API_BASE_URL}/ec2/start`;
			const body = { instanceId: resourceId };
			const res = await fetch(url, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body)
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				alert(`Failed to start: ${err.error || res.status}`);
				setEc2ActionState(prev => ({ ...prev, [resourceId]: undefined }));
			} else {
				setEc2ActionState(prev => ({ ...prev, [resourceId]: 'started' }));
				setTimeout(() => setEc2ActionState(prev => ({ ...prev, [resourceId]: undefined })), 1200);
			}
		} catch (e) {
			console.error('Error starting resource:', e);
			setEc2ActionState(prev => ({ ...prev, [resourceId]: undefined }));
		} finally {
			setControllerLoading(false);
		}
	};

  const stopResource = async (resourceId) => {
		try {
			setControllerLoading(true);
			setEc2ActionState(prev => ({ ...prev, [resourceId]: 'stopping' }));
			const url = `${API_BASE_URL}/ec2/stop`;
			const body = { instanceId: resourceId };
			const res = await fetch(url, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body)
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				alert(`Failed to stop: ${err.error || res.status}`);
				setEc2ActionState(prev => ({ ...prev, [resourceId]: undefined }));
			} else {
				setEc2ActionState(prev => ({ ...prev, [resourceId]: 'stopped' }));
				setTimeout(() => setEc2ActionState(prev => ({ ...prev, [resourceId]: undefined })), 1200);
			}
		} catch (e) {
			console.error('Error stopping resource:', e);
			setEc2ActionState(prev => ({ ...prev, [resourceId]: undefined }));
		} finally {
			setControllerLoading(false);
		}
	};

const enableQueue = async (queueName) => {
		try {
			setControllerLoading(true);
			setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), enable: 'enabling' } }));
      const res = await fetch(`${API_BASE_URL}/sqs/enable/${encodeURIComponent(queueName)}`, { method: 'POST' });
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				alert(`Failed to enable queue: ${err.error || res.status}`);
				setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), enable: undefined } }));
			} else {
				setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), enable: 'enabled' } }));
				setTimeout(() => setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), enable: undefined } })), 1200);
			}
      await fetchControllerStatus('', 'sqs');
		} catch (e) {
			console.error('Error enabling queue:', e);
			setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), enable: undefined } }));
		} finally {
			setControllerLoading(false);
		}
	};

const disableQueue = async (queueName) => {
		try {
			setControllerLoading(true);
			setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), disable: 'disabling' } }));
      const res = await fetch(`${API_BASE_URL}/sqs/disable/${encodeURIComponent(queueName)}`, { method: 'POST' });
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				alert(`Failed to disable queue: ${err.error || res.status}`);
				setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), disable: undefined } }));
			} else {
				setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), disable: 'disabled' } }));
				setTimeout(() => setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), disable: undefined } })), 1200);
			}
      await fetchControllerStatus('', 'sqs');
		} catch (e) {
			console.error('Error disabling queue:', e);
			setSqsActionState(prev => ({ ...prev, [queueName]: { ...(prev[queueName]||{}), disable: undefined } }));
		} finally {
			setControllerLoading(false);
		}
	};

  const invokeLambda = async (functionName) => {
    try {
      setControllerLoading(true);
      setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), invoke: 'invoking' } }));
      const res = await fetch(`${API_BASE_URL}/lambda/invoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ functionName })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(`Failed to invoke: ${err.error || res.status}`);
        setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), invoke: undefined } }));
        return;
      }
      await res.json();
      setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), invoke: 'invoked' } }));
      setTimeout(() => setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), invoke: undefined } })), 1200);
    } catch (e) {
      console.error('Error invoking lambda:', e);
      setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), invoke: undefined } }));
    } finally {
      setControllerLoading(false);
    }
  };

	const enableLambdaConcurrency = async (functionName, concurrentExecutions = 1) => {
		try {
			setControllerLoading(true);
      setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), enable: 'enabling' } }));
      const res = await fetch(`${API_BASE_URL}/lambda/${encodeURIComponent(functionName)}/enable-concurrency`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ concurrentExecutions })
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				alert(`Failed to enable concurrency: ${err.error || res.status}`);
				setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), enable: undefined } }));
			} else {
				setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), enable: 'enabled' } }));
				setTimeout(() => setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), enable: undefined } })), 1200);
				
				// Auto-refresh all Lambda statuses after 3 seconds to show updated concurrency
				setTimeout(() => {
					loadAllLambdaConcurrency();
				}, 3000);
			}
		} catch (e) {
			console.error('Error enabling provisioned concurrency:', e);
			setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), enable: undefined } }));
		} finally {
			setControllerLoading(false);
		}
	};

	const disableLambdaConcurrency = async (functionName) => {
		try {
			setControllerLoading(true);
      setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), disable: 'disabling' } }));
      const res = await fetch(`${API_BASE_URL}/lambda/${encodeURIComponent(functionName)}/disable-concurrency`, { method: 'POST' });
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				alert(`Failed to disable concurrency: ${err.error || res.status}`);
				setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), disable: undefined } }));
			} else {
				setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), disable: 'disabled' } }));
				setTimeout(() => setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), disable: undefined } })), 1200);
				
				// Auto-refresh all Lambda statuses after 2 seconds to show updated concurrency
				setTimeout(() => {
					loadAllLambdaConcurrency();
				}, 2000);
			}
		} catch (e) {
			console.error('Error disabling provisioned concurrency:', e);
			setLambdaActionState(prev => ({ ...prev, [functionName]: { ...(prev[functionName]||{}), disable: undefined } }));
		} finally {
			setControllerLoading(false);
		}
	};

	// Load controller apps when switching to the tab the first time
	useEffect(() => {
		if (isConnected && activeTab === 'controller' && controllerApps.length === 0) {
			fetchApplications();
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [activeTab, isConnected]);

	// Refresh status when selection changes
	useEffect(() => {
		if (isConnected && activeTab === 'controller' && selectedApp) {
			fetchControllerStatus(selectedApp, selectedServiceType);
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [selectedApp, selectedServiceType]);

	// Load SQS details when switching to SQS tab
useEffect(() => {
    if (isConnected && activeTab === 'sqs') {
        fetchControllerStatus('', 'sqs');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
}, [activeTab, isConnected]);

// Auto-load Lambda concurrency status/current for table columns
const loadAllLambdaConcurrency = async (retryCount = 0) => {
    try {
        const names = (awsData.lambda || []).map(f => f.name).filter(Boolean);
        if (names.length === 0) return;
        
        // Add a small delay between requests to avoid overwhelming AWS API
        const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        
        const entries = await Promise.all(names.map(async (name, index) => {
            try {
                // Stagger requests to avoid rate limiting
                if (index > 0) await delay(100);
                
                const res = await fetch(`${API_BASE_URL}/lambda/${encodeURIComponent(name)}/concurrency-status`);
                if (!res.ok) {
                    console.warn(`Failed to fetch status for ${name}: ${res.status}`);
                    return [name, { status: 'unknown' }];
                }
                const data = await res.json();
                return [name, {
                    status: data?.status || 'unknown',
                    current: (typeof data?.provisionedConcurrentExecutions === 'number') ? data.provisionedConcurrentExecutions : undefined
                }];
            } catch (error) {
                console.warn(`Error fetching status for ${name}:`, error);
                return [name, { status: 'unknown' }];
            }
        }));
        
        setLambdaActionState(prev => {
            const next = { ...prev };
            for (const [name, info] of entries) {
                next[name] = { ...(next[name] || {}), ...info };
            }
            return next;
        });
        
        // If we got many 'unknown' statuses and this is the first retry, try again after a delay
        const unknownCount = entries.filter(([_, info]) => info.status === 'unknown').length;
        if (unknownCount > names.length / 2 && retryCount === 0) {
            console.log('Many unknown statuses detected, retrying in 2 seconds...');
            setTimeout(() => loadAllLambdaConcurrency(1), 2000);
        }
    } catch (e) {
        console.error('Error loading lambda concurrency:', e);
    }
};

useEffect(() => {
    if (isConnected && activeTab === 'lambda') {
        loadAllLambdaConcurrency();
    }
}, [isConnected, activeTab, awsData.lambda]);

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'running':
      case 'active':
      case 'available':
        return 'text-green-600 bg-green-100';
      case 'stopped':
      case 'inactive':
        return 'text-red-600 bg-red-100';
      case 'pending':
      case 'stopping':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getLambdaStatusDisplay = (status) => {
    switch (status?.toLowerCase()) {
      case 'enabled':
        return 'Enabled';
      case 'disabled':
        return 'Disabled';
      case 'no_published_version':
        return 'No Published Version';
      case 'unknown':
        return 'Unknown';
      default:
        return status || 'Unknown';
    }
  };

  // Check current provisioned concurrency status/value for a lambda
  const checkLambdaConcurrencyStatus = async (functionName) => {
    try {
      setControllerLoading(true);
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), status: 'checking' }
      }));
      const res = await fetch(`${API_BASE_URL}/lambda/${encodeURIComponent(functionName)}/concurrency-status`);
      if (!res.ok) {
        setLambdaActionState(prev => ({
          ...prev,
          [functionName]: { ...(prev[functionName] || {}), status: 'unknown' }
        }));
        return;
      }
      const data = await res.json();
      const status = data?.status || 'unknown';
      const current = typeof data?.provisionedConcurrentExecutions === 'number'
        ? data.provisionedConcurrentExecutions
        : undefined;
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), status, current }
      }));
      // Keep the result visible briefly for user feedback
      setTimeout(() => {
        setLambdaActionState(prev => ({
          ...prev,
          [functionName]: { ...(prev[functionName] || {}), status: undefined }
        }));
      }, 1500);
    } catch (e) {
      console.error('Error checking lambda concurrency:', e);
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), status: 'unknown' }
      }));
    } finally {
      setControllerLoading(false);
    }
  };

  const fetchLambdaCurrentConcurrency = async (functionName) => {
    try {
      setControllerLoading(true);
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), current: 'fetching' }
      }));
      const res = await fetch(`${API_BASE_URL}/lambda/${encodeURIComponent(functionName)}/concurrency-status`);
      if (!res.ok) {
        setLambdaActionState(prev => ({
          ...prev,
          [functionName]: { ...(prev[functionName] || {}), current: undefined }
        }));
        return;
      }
      const data = await res.json();
      const value = typeof data?.provisionedConcurrentExecutions === 'number'
        ? data.provisionedConcurrentExecutions
        : 0;
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), current: value }
      }));
    } catch (e) {
      console.error('Error fetching current concurrency:', e);
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), current: undefined }
      }));
    } finally {
      setControllerLoading(false);
    }
  };

  // Manual refresh function for Lambda concurrency status
  const refreshLambdaStatus = async (functionName) => {
    try {
      setControllerLoading(true);
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), status: 'checking', current: 'fetching' }
      }));
      const res = await fetch(`${API_BASE_URL}/lambda/${encodeURIComponent(functionName)}/concurrency-status`);
      if (!res.ok) {
        setLambdaActionState(prev => ({
          ...prev,
          [functionName]: { ...(prev[functionName] || {}), status: 'unknown', current: undefined }
        }));
        return;
      }
      const data = await res.json();
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: {
          ...prev[functionName],
          status: data?.status || 'unknown',
          current: typeof data?.provisionedConcurrentExecutions === 'number' ? data.provisionedConcurrentExecutions : undefined
        }
      }));
    } catch (e) {
      console.error('Error refreshing lambda status:', e);
      setLambdaActionState(prev => ({
        ...prev,
        [functionName]: { ...(prev[functionName] || {}), status: 'unknown', current: undefined }
      }));
    } finally {
      setControllerLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'bg-red-50 border-red-200 text-red-800';
      case 'medium': return 'bg-yellow-50 border-yellow-200 text-yellow-800';
      case 'low': return 'bg-blue-50 border-blue-200 text-blue-800';
      default: return 'bg-gray-50 border-gray-200 text-gray-800';
    }
  };

  if (!isConnected) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-purple-900 to-pink-900 flex items-center justify-center p-4">
        <div className="max-w-md w-full">
          <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-8 shadow-2xl border border-white/20">
            <div className="text-center mb-8">
              <div className="mx-auto h-20 w-20 bg-gradient-to-r from-purple-400 to-pink-400 rounded-full flex items-center justify-center mb-4">
                <Cloud className="h-10 w-10 text-white" />
              </div>
              <h1 className="text-3xl font-bold text-white mb-2">AWS Management Dashboard</h1>
              <p className="text-purple-200">Connect to your AWS account to get started</p>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-purple-200 mb-2 flex items-center">
                  <Key className="h-4 w-4 mr-2" />
                  Access Key ID
                </label>
                <input
                  type="text"
                  value={credentials.accessKey}
                  onChange={(e) => setCredentials({...credentials, accessKey: e.target.value})}
                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-purple-300 focus:outline-none focus:ring-2 focus:ring-purple-400"
                  placeholder="Enter your AWS Access Key ID"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-purple-200 mb-2 flex items-center">
                  <Lock className="h-4 w-4 mr-2" />
                  Secret Access Key
                </label>
                <input
                  type="password"
                  value={credentials.secretKey}
                  onChange={(e) => setCredentials({...credentials, secretKey: e.target.value})}
                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white placeholder-purple-300 focus:outline-none focus:ring-2 focus:ring-purple-400"
                  placeholder="Enter your AWS Secret Access Key"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-purple-200 mb-2 flex items-center">
                  <Globe className="h-4 w-4 mr-2" />
                  Region
                </label>
                <select
                  value={credentials.region}
                  onChange={(e) => setCredentials({...credentials, region: e.target.value})}
                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/20 text-white focus:outline-none focus:ring-2 focus:ring-purple-400"
                >
                  <option value="ap-south-1">Asia Pacific (Mumbai)</option>
                  <option value="us-east-1">US East (N. Virginia)</option>
                  <option value="us-west-2">US West (Oregon)</option>
                  <option value="eu-west-1">Europe (Ireland)</option>
                  <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                </select>
              </div>
              
              <button
                onClick={handleConnect}
                disabled={loading || !credentials.accessKey || !credentials.secretKey}
                className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-3 px-4 rounded-lg transition-all duration-200 transform hover:scale-105"
              >
                {loading ? (
                  <div className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Connecting to AWS...
                  </div>
                ) : (
                  'Connect to AWS'
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <div className="h-10 w-10 bg-gradient-to-r from-purple-600 to-pink-600 rounded-lg flex items-center justify-center mr-3">
                <Cloud className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">AWS Management Dashboard</h1>
                <p className="text-sm text-gray-500">Region: {credentials.region}</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={fetchAllResources}
                disabled={refreshing}
                className="flex items-center text-sm text-gray-600 hover:text-gray-900 bg-gray-100 hover:bg-gray-200 px-3 py-2 rounded-lg transition-colors"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <span className="flex items-center text-sm text-gray-600">
                <CheckCircle className="h-4 w-4 text-green-500 mr-2" />
                Connected
              </span>
              <button
                onClick={() => setIsConnected(false)}
                className="text-gray-600 hover:text-gray-900 p-2 rounded-lg hover:bg-gray-100"
              >
                <Settings className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8 overflow-x-auto" aria-label="Tabs">
            {[
              { id: 'overview', name: 'Overview', icon: TrendingUp },
              { id: 'ec2', name: 'EC2 Instances', icon: Server },
              { id: 'rds', name: 'RDS', icon: Database },
              { id: 'lambda', name: 'Lambda', icon: Zap },
              { id: 'sqs', name: 'SQS', icon: MemoryStick },
              { id: 's3', name: 'S3 Buckets', icon: HardDrive },
              { id: 'vpc', name: 'VPC', icon: Network },
              { id: 'iam', name: 'IAM', icon: Users },
              { id: 'cloudwatch', name: 'CloudWatch', icon: Activity },
              { id: 'security', name: 'Security', icon: Shield }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`${
                    activeTab === tab.id
                      ? 'border-purple-500 text-purple-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center`}
                >
                  <Icon className="h-4 w-4 mr-2" />
                  {tab.name}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <div>
            {/* Resource Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">EC2 Instances</p>
                    <p className="text-3xl font-bold text-gray-900">{awsData.ec2?.length || 0}</p>
                    <p className="text-sm text-green-600 mt-1">
                      {awsData.ec2?.filter(i => i.state === 'running')?.length || 0} running
                    </p>
                  </div>
                  <div className="h-12 w-12 bg-blue-100 rounded-lg flex items-center justify-center">
                    <Server className="h-6 w-6 text-blue-600" />
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">RDS Instances</p>
                    <p className="text-3xl font-bold text-gray-900">{awsData.rds?.length || 0}</p>
                    <p className="text-sm text-green-600 mt-1">
                      {awsData.rds?.filter(db => db.state === 'available')?.length || 0} available
                    </p>
                  </div>
                  <div className="h-12 w-12 bg-green-100 rounded-lg flex items-center justify-center">
                    <Database className="h-6 w-6 text-green-600" />
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Lambda Functions</p>
                    <p className="text-3xl font-bold text-gray-900">{awsData.lambda?.length || 0}</p>
                    <p className="text-sm text-green-600 mt-1">
                      {awsData.lambda?.filter(f => f.state === 'Active')?.length || 0} active
                    </p>
                  </div>
                  <div className="h-12 w-12 bg-yellow-100 rounded-lg flex items-center justify-center">
                    <Zap className="h-6 w-6 text-yellow-600" />
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Security Alerts</p>
                    <p className="text-3xl font-bold text-gray-900">{awsData.security_alerts?.length || 0}</p>
                    <p className="text-sm text-red-600 mt-1">
                      {awsData.security_alerts?.filter(a => a.severity === 'high')?.length || 0} critical
                    </p>
                  </div>
                  <div className="h-12 w-12 bg-red-100 rounded-lg flex items-center justify-center">
                    <AlertTriangle className="h-6 w-6 text-red-600" />
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-200 hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">CloudWatch Metrics</p>
                    <p className="text-3xl font-bold text-gray-900">
                      {Object.keys(awsData.cloudwatch_metrics || {}).length}
                    </p>
                    <p className="text-sm text-blue-600 mt-1">
                      {awsData.cloudwatch_metrics?.ec2_cpu?.length || 0} active
                    </p>
                  </div>
                  <div className="h-12 w-12 bg-blue-100 rounded-lg flex items-center justify-center">
                    <Activity className="h-6 w-6 text-blue-600" />
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Security Alerts */}
            {awsData.security_alerts?.length > 0 && (
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 mb-8">
                <div className="px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                    <Shield className="h-5 w-5 mr-2 text-red-500" />
                    Recent Security Alerts
                  </h2>
                </div>
                <div className="p-6">
                  <div className="space-y-3">
                    {awsData.security_alerts.slice(0, 3).map((alert, index) => (
                      <div key={index} className={`rounded-lg p-4 border ${getSeverityColor(alert.severity)}`}>
                        <div className="flex items-start justify-between">
                          <div className="flex items-center">
                            <AlertCircle className="h-5 w-5 mr-3 flex-shrink-0" />
                            <div>
                              <p className="font-medium">{alert.message}</p>
                              <p className="text-sm opacity-75 mt-1">
                                {alert.service} • {new Date(alert.timestamp).toLocaleDateString()}
                              </p>
                            </div>
                          </div>
                          <span className="text-xs font-medium px-2 py-1 rounded uppercase">
                            {alert.severity}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'ec2' && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Server className="h-5 w-5 mr-2" />
                EC2 Instances ({awsData.ec2?.length || 0})
              </h2>
              <input
                type="text"
                value={activeTab==='ec2'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search instances..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Instance</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">State</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Addresses</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">AZ</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {(awsData.ec2||[]).filter((i)=>{
                    const q = searchQuery.toLowerCase();
                    if (!q) return true;
                    return (i.name||'').toLowerCase().includes(q) || (i.instance_id||'').toLowerCase().includes(q) || (i.instance_type||'').toLowerCase().includes(q);
                  }).map((instance) => (
                    <tr key={instance.instance_id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className="text-sm font-medium text-gray-900">{instance.name}</div>
                          <div className="text-sm text-gray-500">{instance.instance_id}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(instance.state)}`}>
                          {instance.state === 'running' ? <Play className="h-3 w-3 mr-1" /> : <Pause className="h-3 w-3 mr-1" />}
                          {instance.state}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{instance.instance_type}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        <div>Public: {instance.public_ip}</div>
                        <div>Private: {instance.private_ip}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        <span className="flex items-center">
                          <MapPin className="h-3 w-3 mr-1" />
                          {instance.availability_zone}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <div className="flex items-center gap-2">
                          <button onClick={() => startResource(instance.instance_id)} className="px-3 py-1.5 rounded-full bg-green-600 hover:bg-green-700 text-white text-xs font-semibold shadow-sm">
                            {ec2ActionState[instance.instance_id] === 'starting' ? 'Starting' : ec2ActionState[instance.instance_id] === 'started' ? 'Started' : 'Start'}
                          </button>
                          <button onClick={() => stopResource(instance.instance_id)} className="px-3 py-1.5 rounded-full bg-red-600 hover:bg-red-700 text-white text-xs font-semibold shadow-sm">
                            {ec2ActionState[instance.instance_id] === 'stopping' ? 'Stopping' : ec2ActionState[instance.instance_id] === 'stopped' ? 'Stopped' : 'Stop'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'rds' && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Database className="h-5 w-5 mr-2" />
                RDS Instances ({awsData.rds?.length || 0})
              </h2>
              <input
                type="text"
                value={activeTab==='rds'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search RDS..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <div className="p-6">
              <div className="grid gap-6">
                {(awsData.rds||[]).filter((db)=>{
                  const q = searchQuery.toLowerCase();
                  if (!q) return true; return (db.name||'').toLowerCase().includes(q) || (db.engine||'').toLowerCase().includes(q);
                }).map((db) => (
                  <div key={db.name} className="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900">{db.name}</h3>
                        <p className="text-sm text-gray-500">{db.engine} {db.engine_version}</p>
                      </div>
                      <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(db.state)}`}>
                        {db.state}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <p className="text-gray-500">Instance Class</p>
                        <p className="font-medium">{db.instance_class}</p>
                      </div>
                      <div>
                        <p className="text-gray-500">Storage</p>
                        <p className="font-medium">{db.allocated_storage} GB</p>
                      </div>
                      <div>
                        <p className="text-gray-500">Multi-AZ</p>
                        <p className="font-medium">{db.multi_az ? 'Yes' : 'No'}</p>
                      </div>
                      <div>
                        <p className="text-gray-500">Public Access</p>
                        <p className={`font-medium ${db.publicly_accessible ? 'text-red-600' : 'text-green-600'}`}>
                          {db.publicly_accessible ? 'Yes' : 'No'}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'lambda' && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Zap className="h-5 w-5 mr-2" />
                Lambda Functions ({awsData.lambda?.length || 0})
              </h2>
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={activeTab==='lambda'?searchQuery:''}
                  onChange={(e)=> setSearchQuery(e.target.value)}
                  placeholder="Search Lambda..."
                  className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
                <button 
                  onClick={loadAllLambdaConcurrency}
                  className="px-4 py-2 rounded-full bg-purple-600 hover:bg-purple-700 text-white text-sm font-semibold shadow-sm flex items-center gap-2"
                >
                  <RefreshCw className="h-4 w-4" />
                  Refresh All
                </button>
              </div>
            </div>
            <div className="p-6">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Function name</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Package type</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Runtime</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last modified</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Current Concurrency</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {(awsData.lambda||[]).filter((f)=>{
                      const q = searchQuery.toLowerCase();
                      if (!q) return true; return (f.name||'').toLowerCase().includes(q) || (f.runtime||'').toLowerCase().includes(q);
                    }).map((func) => (
                      <tr key={func.name} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm font-medium text-gray-900">{func.name}</div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{func.package_type || (func.runtime ? 'Zip' : 'Image')}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{func.runtime || '-'}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{func.last_modified ? new Date(func.last_modified).toLocaleDateString() : '-'}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${lambdaActionState[func.name]?.status === 'enabled' ? 'bg-green-100 text-green-700' : lambdaActionState[func.name]?.status === 'disabled' ? 'bg-red-100 text-red-700' : lambdaActionState[func.name]?.status === 'no_published_version' ? 'bg-yellow-100 text-yellow-700' : 'bg-gray-100 text-gray-700'}`}>
                            {getLambdaStatusDisplay(lambdaActionState[func.name]?.status)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                          {typeof lambdaActionState[func.name]?.current === 'number' ? lambdaActionState[func.name]?.current : '-'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <div className="flex items-center gap-2">
                            <button onClick={() => invokeLambda(func.name)} className="px-3 py-1.5 rounded-full bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-sm">
                              {lambdaActionState[func.name]?.invoke === 'invoking' ? 'Invoking' : lambdaActionState[func.name]?.invoke === 'invoked' ? 'Invoked' : 'Invoke'}
                            </button>
                            <button onClick={() => enableLambdaConcurrency(func.name, 1)} className="px-3 py-1.5 rounded-full bg-green-600 hover:bg-green-700 text-white text-xs font-semibold shadow-sm">
                              {lambdaActionState[func.name]?.enable === 'enabling' ? 'Enabling' : lambdaActionState[func.name]?.enable === 'enabled' ? 'Enabled' : 'Enable Concurrency'}
                            </button>
                            <button onClick={() => disableLambdaConcurrency(func.name)} className="px-3 py-1.5 rounded-full bg-red-600 hover:bg-red-700 text-white text-xs font-semibold shadow-sm">
                              {lambdaActionState[func.name]?.disable === 'disabling' ? 'Disabling' : lambdaActionState[func.name]?.disable === 'disabled' ? 'Disabled' : 'Disable Concurrency'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 's3' && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <HardDrive className="h-5 w-5 mr-2" />
                S3 Buckets ({awsData.s3?.length || 0})
              </h2>
              <input
                type="text"
                value={activeTab==='s3'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search buckets..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Bucket Name</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Region</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Objects</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Size</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {(awsData.s3||[]).filter((b)=>{
                    const q = searchQuery.toLowerCase(); if (!q) return true; return (b.name||'').toLowerCase().includes(q) || (b.region||'').toLowerCase().includes(q);
                  }).map((bucket) => (
                    <tr key={bucket.name} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <Folder className="h-4 w-4 text-blue-500 mr-2" />
                          <div className="text-sm font-medium text-gray-900">{bucket.name}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{bucket.region}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{bucket.objects}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{bucket.size}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(bucket.creation_date).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'sqs' && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <MemoryStick className="h-5 w-5 mr-2" />
                SQS Queues
              </h2>
              <input
                type="text"
                value={activeTab==='sqs'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search queues..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <div className="p-6">
              {/* Removed inner refresh; global header refresh is sufficient */}
              {/* Rich table with AWS-like columns */}
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Messages available</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Messages in flight</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Encryption</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                  {(controllerResources || []).filter((q)=>{
                    const ql = searchQuery.toLowerCase(); if (!ql) return true; return (q.resourceId||'').toLowerCase().includes(ql);
                  }).map((q) => {
                      const attrs = q.attributes || {};
                      const created = attrs.CreatedTimestamp ? new Date(parseInt(attrs.CreatedTimestamp, 10) * 1000) : null;
                      const modified = attrs.LastModifiedTimestamp ? new Date(parseInt(attrs.LastModifiedTimestamp, 10) * 1000) : null;
                      const isFifo = (q.resourceId || '').toLowerCase().endsWith('.fifo');
                      const available = attrs.ApproximateNumberOfMessages ? parseInt(attrs.ApproximateNumberOfMessages, 10) : 0;
                      const inFlight = attrs.ApproximateNumberOfMessagesNotVisible ? parseInt(attrs.ApproximateNumberOfMessagesNotVisible, 10) : 0;
                      const encryption = 'Amazon SQS key (SSE-SQS)';
                      return (
                        <tr key={q.resourceId} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{q.resourceId}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{isFifo ? 'FIFO' : 'Standard'}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{created ? created.toISOString() : '-'}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{available}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{inFlight}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700">{encryption}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <div className="flex items-center gap-2">
                              <button onClick={async () => {
                                try {
                                  const res = await fetch(`${API_BASE_URL}/sqs/status/${encodeURIComponent(q.resourceId)}`);
                                  const data = await res.json();
                                  alert(`Messages available: ${data.ApproximateNumberOfMessages || 0}\nIn flight: ${data.ApproximateNumberOfMessagesNotVisible || 0}`);
                                } catch (e) {}
                              }} className="px-3 py-1.5 rounded-full bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-sm">
                                {sqsActionState[q.resourceId]?.status === 'checking' ? 'Checking' : 'Status'}
                              </button>
                              <button onClick={() => enableQueue(q.resourceId)} className="px-3 py-1.5 rounded-full bg-green-600 hover:bg-green-700 text-white text-xs font-semibold shadow-sm">
                                {sqsActionState[q.resourceId]?.enable === 'enabling' ? 'Enabling' : sqsActionState[q.resourceId]?.enable === 'enabled' ? 'Enabled' : 'Enable'}
                              </button>
                              <button onClick={() => disableQueue(q.resourceId)} className="px-3 py-1.5 rounded-full bg-red-600 hover:bg-red-700 text-white text-xs font-semibold shadow-sm">
                                {sqsActionState[q.resourceId]?.disable === 'disabling' ? 'Disabling' : sqsActionState[q.resourceId]?.disable === 'disabled' ? 'Disabled' : 'Disable'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'vpc' && (
          <div className="space-y-6">
            {/* VPCs */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Network className="h-5 w-5 mr-2" />
                VPCs ({awsData.vpc?.length || 0})
              </h2>
              <input
                type="text"
                value={activeTab==='vpc'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search VPCs..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
              <div className="p-6">
                <div className="grid gap-4">
                  {awsData.vpc?.map((vpc) => (
                    <div key={vpc.id} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-semibold text-gray-900">{vpc.name}</h3>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(vpc.state)}`}>
                          {vpc.state}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <p className="text-gray-500">VPC ID</p>
                          <p className="font-medium">{vpc.id}</p>
                        </div>
                        <div>
                          <p className="text-gray-500">CIDR Block</p>
                          <p className="font-medium">{vpc.cidr_block}</p>
                        </div>
                        <div>
                          <p className="text-gray-500">Subnets</p>
                          <p className="font-medium">{vpc.subnet_count}</p>
                        </div>
                        <div>
                          <p className="text-gray-500">Default</p>
                          <p className={`font-medium ${vpc.is_default ? 'text-blue-600' : 'text-gray-900'}`}>
                            {vpc.is_default ? 'Yes' : 'No'}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Subnets */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Network className="h-5 w-5 mr-2" />
                Subnets ({awsData.subnets?.length || 0})
              </h2>
              <input
                type="text"
                value={activeTab==='vpc'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search subnets..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subnet ID</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">VPC</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CIDR</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">AZ</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Available IPs</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {awsData.subnets?.map((subnet) => (
                      <tr key={subnet.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{subnet.name}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{subnet.id}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{subnet.vpc_id}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{subnet.cidr_block}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{subnet.availability_zone}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{subnet.available_ip_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'iam' && (
          <div className="space-y-6">
            {/* IAM Users */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Users className="h-5 w-5 mr-2" />
                IAM Users ({awsData.iam_users?.length || 0})
              </h2>
              <input
                type="text"
                value={activeTab==='iam'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search users..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User Name</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Login</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Policies</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {awsData.iam_users?.map((user) => (
                      <tr key={user.name} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm font-medium text-gray-900">{user.name}</div>
                          <div className="text-sm text-gray-500">{user.user_id}</div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(user.creation_date).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {user.password_last_used === 'Never' ? 'Never' : new Date(user.password_last_used).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.attached_policies}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* IAM Roles */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Shield className="h-5 w-5 mr-2" />
                IAM Roles ({awsData.iam_roles?.length || 0})
              </h2>
              <input
                type="text"
                value={activeTab==='iam'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search roles..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
              <div className="p-6">
                <div className="grid gap-4">
                  {awsData.iam_roles?.map((role) => (
                    <div key={role.name} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-semibold text-gray-900">{role.name}</h3>
                        <span className="text-xs text-gray-500">
                          Created: {new Date(role.creation_date).toLocaleDateString()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mb-2">{role.description}</p>
                      <div className="text-xs text-gray-500">
                        Max Session: {Math.floor(role.max_session_duration / 3600)}h
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'cloudwatch' && (
          <div className="space-y-6">
            {/* CloudWatch Metrics */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Activity className="h-5 w-5 mr-2" />
                CloudWatch Metrics
              </h2>
              <input
                type="text"
                value={activeTab==='cloudwatch'?searchQuery:''}
                onChange={(e)=> setSearchQuery(e.target.value)}
                placeholder="Search metrics..."
                className="w-full md:w-72 px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {/* EC2 CPU Metrics */}
                  <div className="border border-gray-200 rounded-lg p-4">
                    <h3 className="font-semibold text-gray-900 mb-3 flex items-center">
                      <Server className="h-4 w-4 mr-2" />
                      EC2 CPU Utilization
                    </h3>
                    {awsData.cloudwatch_metrics?.ec2_cpu?.length > 0 ? (
                      <div className="space-y-2">
                        {awsData.cloudwatch_metrics.ec2_cpu.slice(0, 3).map((metric, index) => (
                          <div key={index} className="text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-600">Average:</span>
                              <span className="font-medium">{metric.Average?.toFixed(2)}%</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-600">Maximum:</span>
                              <span className="font-medium">{metric.Maximum?.toFixed(2)}%</span>
                            </div>
                            <div className="text-xs text-gray-500 mt-1">
                              {new Date(metric.Timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-500 text-sm">No EC2 CPU metrics available</p>
                    )}
                  </div>

                  {/* RDS CPU Metrics */}
                  <div className="border border-gray-200 rounded-lg p-4">
                    <h3 className="font-semibold text-gray-900 mb-3 flex items-center">
                      <Database className="h-4 w-4 mr-2" />
                      RDS CPU Utilization
                    </h3>
                    {awsData.cloudwatch_metrics?.rds_cpu?.length > 0 ? (
                      <div className="space-y-2">
                        {awsData.cloudwatch_metrics.rds_cpu.slice(0, 3).map((metric, index) => (
                          <div key={index} className="text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-600">Average:</span>
                              <span className="font-medium">{metric.Average?.toFixed(2)}%</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-600">Maximum:</span>
                              <span className="font-medium">{metric.Maximum?.toFixed(2)}%</span>
                            </div>
                            <div className="text-xs text-gray-500 mt-1">
                              {new Date(metric.Timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-500 text-sm">No RDS CPU metrics available</p>
                    )}
                  </div>

                  {/* Lambda Duration Metrics */}
                  <div className="border border-gray-200 rounded-lg p-4">
                    <h3 className="font-semibold text-gray-900 mb-3 flex items-center">
                      <Zap className="h-4 w-4 mr-2" />
                      Lambda Duration
                    </h3>
                    {awsData.cloudwatch_metrics?.lambda_duration?.length > 0 ? (
                      <div className="space-y-2">
                        {awsData.cloudwatch_metrics.lambda_duration.slice(0, 3).map((metric, index) => (
                          <div key={index} className="text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-600">Average:</span>
                              <span className="font-medium">{(metric.Average / 1000).toFixed(2)}s</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-600">Maximum:</span>
                              <span className="font-medium">{(metric.Maximum / 1000).toFixed(2)}s</span>
                            </div>
                            <div className="text-xs text-gray-500 mt-1">
                              {new Date(metric.Timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-500 text-sm">No Lambda duration metrics available</p>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* CloudWatch Logs */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                  <Clock className="h-5 w-5 mr-2" />
                  Recent CloudWatch Logs
                </h2>
              </div>
              <div className="p-6">
                {awsData.cloudwatch_logs?.recent_events?.length > 0 ? (
                  <div className="space-y-3">
                    {awsData.cloudwatch_logs.recent_events.slice(0, 5).map((event, index) => (
                      <div key={index} className="border border-gray-200 rounded-lg p-3 bg-gray-50">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <p className="text-sm font-medium text-gray-900">
                              {event.logStreamName || 'Unknown Stream'}
                            </p>
                            <p className="text-xs text-gray-600 mt-1">
                              {event.message?.substring(0, 100)}...
                            </p>
                          </div>
                          <div className="text-xs text-gray-500 ml-3">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Clock className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                    <p className="text-gray-500">No recent log events available</p>
                    <p className="text-sm text-gray-400 mt-1">Logs will appear here when available</p>
                  </div>
                )}
              </div>
            </div>

            {/* CloudWatch Alarms */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                  <AlertTriangle className="h-5 w-5 mr-2" />
                  CloudWatch Alarms ({awsData.cloudwatch_alarms?.alarms?.length || 0})
                </h2>
              </div>
              <div className="p-6">
                {awsData.cloudwatch_alarms?.alarms?.length > 0 ? (
                  <div className="space-y-3">
                    {awsData.cloudwatch_alarms.alarms.slice(0, 5).map((alarm, index) => (
                      <div key={index} className={`border rounded-lg p-4 ${
                        alarm.StateValue === 'ALARM' ? 'border-red-200 bg-red-50' :
                        alarm.StateValue === 'OK' ? 'border-green-200 bg-green-50' :
                        'border-yellow-200 bg-yellow-50'
                      }`}>
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <h3 className="font-semibold text-gray-900">{alarm.AlarmName}</h3>
                            <p className="text-sm text-gray-600 mt-1">{alarm.AlarmDescription || 'No description'}</p>
                            <div className="mt-2 text-xs text-gray-500">
                              <p>Metric: {alarm.MetricName}</p>
                              <p>Namespace: {alarm.Namespace}</p>
                            </div>
                          </div>
                          <div className="ml-4">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              alarm.StateValue === 'ALARM' ? 'bg-red-100 text-red-800' :
                              alarm.StateValue === 'OK' ? 'bg-green-100 text-green-800' :
                              'bg-yellow-100 text-yellow-800'
                            }`}>
                              {alarm.StateValue}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                    <p className="text-gray-500">No CloudWatch alarms configured</p>
                    <p className="text-sm text-gray-400 mt-1">Alarms will appear here when configured</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'security' && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900 flex items-center">
                <Shield className="h-5 w-5 mr-2 text-red-500" />
                Security Analysis ({awsData.security_alerts?.length || 0} alerts)
              </h2>
            </div>
            <div className="p-6">
              {awsData.security_alerts?.length > 0 ? (
                <div className="space-y-4">
                  {awsData.security_alerts.map((alert, index) => (
                    <div key={index} className={`rounded-lg p-6 border-2 ${getSeverityColor(alert.severity)}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex items-center">
                          <AlertCircle className="h-6 w-6 mr-4 flex-shrink-0" />
                          <div>
                            <h3 className="font-semibold text-lg">{alert.message}</h3>
                            <div className="mt-2 text-sm opacity-75">
                              <p><strong>Service:</strong> {alert.service}</p>
                              <p><strong>Resource:</strong> {alert.resource}</p>
                              <p><strong>Detected:</strong> {new Date(alert.timestamp).toLocaleString()}</p>
                            </div>
                          </div>
                        </div>
                        <span className="text-sm font-bold px-3 py-1 rounded uppercase">
                          {alert.severity} PRIORITY
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
                  <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">No Security Issues Detected</h3>
                  <p className="text-gray-500">Your AWS resources appear to be following security best practices.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Service Controller removed per request */}
      </div>
    </div>
  );
};

export default AWSManagementDashboard; 