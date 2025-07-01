"use client"

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { 
  BarChart3, 
  Settings, 
  Eye, 
  AlertTriangle, 
  CheckCircle, 
  ExternalLink,
  RefreshCw,
  Plus,
  Edit,
  Trash2,
  Activity,
  Clock,
  Users,
  Database,
  TrendingUp,
  Bell
} from 'lucide-react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

/**
 * Mock Grafana Data
 */
const MOCK_DASHBOARDS = [
  {
    id: 'dash-001',
    name: 'Security Overview',
    description: 'Comprehensive security monitoring dashboard',
    panels: 12,
    views: 2847,
    alerts: 3,
    status: 'active',
    lastUpdated: '2 minutes ago',
    url: 'https://grafana.aiGuardian.com/d/security-overview'
  },
  {
    id: 'dash-002',
    name: 'System Performance',
    description: 'Infrastructure and application performance metrics',
    panels: 8,
    views: 1923,
    alerts: 1,
    status: 'active',
    lastUpdated: '5 minutes ago',
    url: 'https://grafana.aiGuardian.com/d/system-performance'
  },
  {
    id: 'dash-003',
    name: 'Vulnerability Trends',
    description: 'Vulnerability detection and remediation tracking',
    panels: 6,
    views: 1456,
    alerts: 2,
    status: 'maintenance',
    lastUpdated: '1 hour ago',
    url: 'https://grafana.aiGuardian.com/d/vulnerability-trends'
  }
];

const MOCK_ALERTS = [
  {
    id: 'alert-001',
    name: 'High CPU Usage',
    description: 'CPU usage above 80% for more than 5 minutes',
    severity: 'critical',
    dashboard: 'System Performance',
    triggered: '3 minutes ago',
    status: 'firing'
  },
  {
    id: 'alert-002',
    name: 'Critical Vulnerabilities Detected',
    description: 'New critical vulnerabilities found in code scan',
    severity: 'high',
    dashboard: 'Security Overview',
    triggered: '15 minutes ago',
    status: 'firing'
  },
  {
    id: 'alert-003',
    name: 'Database Connection Issues',
    description: 'Database connection pool exhausted',
    severity: 'warning',
    dashboard: 'System Performance',
    triggered: '1 hour ago',
    status: 'resolved'
  }
];

/**
 * Grafana Configuration Component
 */
const GrafanaConfiguration = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [config, setConfig] = useState({
    serverUrl: 'https://grafana.aiGuardian.com',
    apiKey: '••••••••••••••••••••••••••••••••',
    orgId: '1',
    timeout: 30,
    enableAlerts: true,
    enableNotifications: true,
    syncInterval: 5
  });

  const handleSave = () => {
    console.log('Saving Grafana configuration:', config);
  };

  return (
    <Card className={`
      transition-all duration-300
      ${isDark 
        ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
        : 'border-gray-200 bg-white/80 backdrop-blur-sm'
      }
    `}>
      <CardHeader>
        <CardTitle className={`
          flex items-center transition-colors
          ${isDark ? 'text-zinc-100' : 'text-gray-900'}
        `}>
          <Settings className="w-5 h-5 mr-2" />
          Grafana Configuration
        </CardTitle>
        <CardDescription className={`
          transition-colors
          ${isDark ? 'text-zinc-400' : 'text-gray-600'}
        `}>
          Configure your Grafana server connection and settings
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Server URL
              </Label>
              <Input
                value={config.serverUrl}
                onChange={(e) => setConfig({...config, serverUrl: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                API Key
              </Label>
              <Input
                type="password"
                value={config.apiKey}
                onChange={(e) => setConfig({...config, apiKey: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Organization ID
              </Label>
              <Input
                value={config.orgId}
                onChange={(e) => setConfig({...config, orgId: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
          </div>
          
          <div className="space-y-4">
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Connection Timeout (seconds)
              </Label>
              <Input
                type="number"
                value={config.timeout}
                onChange={(e) => setConfig({...config, timeout: parseInt(e.target.value)})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Sync Interval (minutes)
              </Label>
              <Input
                type="number"
                value={config.syncInterval}
                onChange={(e) => setConfig({...config, syncInterval: parseInt(e.target.value)})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                  Enable Alerts
                </Label>
                <Switch
                  checked={config.enableAlerts}
                  onCheckedChange={(checked) => setConfig({...config, enableAlerts: checked})}
                />
              </div>
              
              <div className="flex items-center justify-between">
                <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                  Enable Notifications
                </Label>
                <Switch
                  checked={config.enableNotifications}
                  onCheckedChange={(checked) => setConfig({...config, enableNotifications: checked})}
                />
              </div>
            </div>
          </div>
        </div>
        
        <div className="flex items-center space-x-3 pt-4 border-t border-zinc-700">
          <Button onClick={handleSave} className="bg-blue-600 hover:bg-blue-700 text-white">
            Save Configuration
          </Button>
          <Button variant="outline" className={`
            ${isDark 
              ? 'border-zinc-700 text-zinc-300 hover:bg-zinc-800' 
              : 'border-gray-300 text-gray-700 hover:bg-gray-50'
            }
          `}>
            Test Connection
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Dashboard Management Component
 */
const DashboardManagement = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [dashboards, setDashboards] = useState(MOCK_DASHBOARDS);

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'text-green-400 border-green-400';
      case 'maintenance': return 'text-yellow-400 border-yellow-400';
      case 'error': return 'text-red-400 border-red-400';
      default: return 'text-gray-400 border-gray-400';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className={`text-lg font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
          Grafana Dashboards
        </h3>
        <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white">
          <Plus className="w-4 h-4 mr-2" />
          Import Dashboard
        </Button>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {dashboards.map((dashboard) => (
          <Card key={dashboard.id} className={`
            transition-all duration-300 hover:scale-105
            ${isDark 
              ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
              : 'border-gray-200 bg-white/80 backdrop-blur-sm'
            }
          `}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className={`
                  text-base font-semibold transition-colors
                  ${isDark ? 'text-zinc-100' : 'text-gray-900'}
                `}>
                  {dashboard.name}
                </CardTitle>
                <Badge variant="outline" className={getStatusColor(dashboard.status)}>
                  {dashboard.status}
                </Badge>
              </div>
              <CardDescription className={`
                transition-colors
                ${isDark ? 'text-zinc-400' : 'text-gray-600'}
              `}>
                {dashboard.description}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-3 gap-4 text-center">
                <div>
                  <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {dashboard.panels}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Panels
                  </div>
                </div>
                <div>
                  <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {dashboard.views}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Views
                  </div>
                </div>
                <div>
                  <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {dashboard.alerts}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Alerts
                  </div>
                </div>
              </div>
              
              <div className="flex items-center justify-between pt-2 border-t border-zinc-700">
                <span className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Updated {dashboard.lastUpdated}
                </span>
                <div className="flex items-center space-x-1">
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Eye className="w-4 h-4" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Edit className="w-4 h-4" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <ExternalLink className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

/**
 * Alert Management Component
 */
const AlertManagement = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [alerts, setAlerts] = useState(MOCK_ALERTS);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400 border-red-400 bg-red-500/10';
      case 'high': return 'text-orange-400 border-orange-400 bg-orange-500/10';
      case 'warning': return 'text-yellow-400 border-yellow-400 bg-yellow-500/10';
      case 'info': return 'text-blue-400 border-blue-400 bg-blue-500/10';
      default: return 'text-gray-400 border-gray-400 bg-gray-500/10';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'firing': return 'text-red-400 border-red-400';
      case 'resolved': return 'text-green-400 border-green-400';
      case 'pending': return 'text-yellow-400 border-yellow-400';
      default: return 'text-gray-400 border-gray-400';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className={`text-lg font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
          Active Alerts
        </h3>
        <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white">
          <Plus className="w-4 h-4 mr-2" />
          Create Alert
        </Button>
      </div>
      
      <div className="space-y-3">
        {alerts.map((alert) => (
          <Card key={alert.id} className={`
            transition-all duration-300
            ${isDark 
              ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
              : 'border-gray-200 bg-white/80 backdrop-blur-sm'
            }
          `}>
            <CardContent className="p-4">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      {alert.name}
                    </h4>
                    <Badge variant="outline" className={getSeverityColor(alert.severity)}>
                      {alert.severity}
                    </Badge>
                    <Badge variant="outline" className={getStatusColor(alert.status)}>
                      {alert.status}
                    </Badge>
                  </div>
                  <p className={`text-sm mb-2 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    {alert.description}
                  </p>
                  <div className="flex items-center space-x-4 text-xs">
                    <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                      Dashboard: {alert.dashboard}
                    </span>
                    <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                      Triggered: {alert.triggered}
                    </span>
                  </div>
                </div>
                <div className="flex items-center space-x-1">
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Eye className="w-4 h-4" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Edit className="w-4 h-4" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Bell className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

/**
 * Main Grafana Integration Component
 */
const GrafanaIntegration = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');

  // Mock metrics data
  const [metricsData] = useState(() => {
    const data = [];
    for (let i = 23; i >= 0; i--) {
      const time = new Date(Date.now() - i * 60 * 60 * 1000);
      data.push({
        time: time.toISOString(),
        dashboardViews: Math.floor(Math.random() * 100 + 50),
        alertsFired: Math.floor(Math.random() * 10),
        dataQueries: Math.floor(Math.random() * 500 + 200),
        responseTime: Math.random() * 50 + 20,
      });
    }
    return data;
  });

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className={`text-2xl font-bold transition-colors ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Grafana Integration
          </h2>
          <p className={`transition-colors ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Monitor and manage your Grafana dashboards and alerts
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-green-400 border-green-400">
            <CheckCircle className="w-3 h-3 mr-1" />
            Connected
          </Badge>
          <Button variant="outline" size="sm" className={`
            ${isDark 
              ? 'border-zinc-700 text-zinc-300 hover:bg-zinc-800' 
              : 'border-gray-300 text-gray-700 hover:bg-gray-50'
            }
          `}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Sync Now
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-4 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Overview
          </TabsTrigger>
          <TabsTrigger value="dashboards" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Dashboards
          </TabsTrigger>
          <TabsTrigger value="alerts" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Alerts
          </TabsTrigger>
          <TabsTrigger value="config" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Configuration
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Metrics Overview */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Total Dashboards', value: '12', icon: BarChart3, color: 'text-blue-400' },
              { title: 'Active Alerts', value: '3', icon: AlertTriangle, color: 'text-red-400' },
              { title: 'Daily Views', value: '2.4K', icon: Eye, color: 'text-green-400' },
              { title: 'Avg Response Time', value: '45ms', icon: Clock, color: 'text-purple-400' }
            ].map((metric, index) => (
              <Card key={index} className={`
                transition-all duration-300 hover:scale-105
                ${isDark 
                  ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
                  : 'border-gray-200 bg-white/80 backdrop-blur-sm'
                }
              `}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className={`text-sm font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {metric.title}
                  </CardTitle>
                  <metric.icon className={`h-4 w-4 ${metric.color}`} />
                </CardHeader>
                <CardContent>
                  <div className={`text-2xl font-bold ${isDark ? 'text-zinc-50' : 'text-gray-900'}`}>
                    {metric.value}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Usage Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className={`
              ${isDark 
                ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
                : 'border-gray-200 bg-white/80 backdrop-blur-sm'
              }
            `}>
              <CardHeader>
                <CardTitle className={isDark ? 'text-zinc-100' : 'text-gray-900'}>
                  Dashboard Views (24h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={metricsData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                    <XAxis 
                      dataKey="time" 
                      tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                      stroke={isDark ? "#9CA3AF" : "#6B7280"}
                      fontSize={10}
                    />
                    <YAxis stroke={isDark ? "#9CA3AF" : "#6B7280"} fontSize={10} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#18181b' : '#ffffff', 
                        border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}
                      labelStyle={{ color: isDark ? '#fafafa' : '#1f2937' }}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="dashboardViews" 
                      stroke="#3B82F6" 
                      fill="#3B82F6"
                      fillOpacity={0.2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className={`
              ${isDark 
                ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
                : 'border-gray-200 bg-white/80 backdrop-blur-sm'
              }
            `}>
              <CardHeader>
                <CardTitle className={isDark ? 'text-zinc-100' : 'text-gray-900'}>
                  Alert Activity (24h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={metricsData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                    <XAxis 
                      dataKey="time" 
                      tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                      stroke={isDark ? "#9CA3AF" : "#6B7280"}
                      fontSize={10}
                    />
                    <YAxis stroke={isDark ? "#9CA3AF" : "#6B7280"} fontSize={10} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#18181b' : '#ffffff', 
                        border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}
                      labelStyle={{ color: isDark ? '#fafafa' : '#1f2937' }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="alertsFired" 
                      stroke="#EF4444" 
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="dashboards" className="mt-6">
          <DashboardManagement />
        </TabsContent>

        <TabsContent value="alerts" className="mt-6">
          <AlertManagement />
        </TabsContent>

        <TabsContent value="config" className="mt-6">
          <GrafanaConfiguration />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default GrafanaIntegration; 