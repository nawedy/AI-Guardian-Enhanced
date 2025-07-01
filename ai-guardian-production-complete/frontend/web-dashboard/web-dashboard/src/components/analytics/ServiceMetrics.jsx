"use client"

import { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Server, 
  Shield, 
  Scan, 
  Brain, 
  Network, 
  Cloud, 
  MessageSquare, 
  Settings,
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  TrendingDown,
  RefreshCw
} from 'lucide-react';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import KPIEngine, { useKPIData } from './KPIEngine';
import { useTheme } from '../darkmode/ThemeProvider';

/**
 * Service Configuration
 */
const SERVICES = {
  'api-gateway': {
    name: 'API Gateway',
    icon: Server,
    description: 'Central API management and routing',
    color: 'bg-blue-500',
    endpoints: ['/auth', '/scan', '/analyze', '/report'],
  },
  'code-scanner': {
    name: 'Code Scanner',
    icon: Scan,
    description: 'Static code analysis and vulnerability detection',
    color: 'bg-green-500',
    endpoints: ['/scan', '/analyze', '/report'],
  },
  'adaptive-learning': {
    name: 'Adaptive Learning',
    icon: Brain,
    description: 'Machine learning model training and inference',
    color: 'bg-purple-500',
    endpoints: ['/train', '/predict', '/feedback'],
  },
  'intelligent-analysis': {
    name: 'Intelligent Analysis',
    icon: Shield,
    description: 'Advanced threat detection and analysis',
    color: 'bg-red-500',
    endpoints: ['/analyze', '/detect', '/classify'],
  },
  'integrations-service': {
    name: 'Integrations',
    icon: Network,
    description: 'Third-party service integrations',
    color: 'bg-orange-500',
    endpoints: ['/webhook', '/notify', '/sync'],
  },
  'communications-service': {
    name: 'Communications',
    icon: MessageSquare,
    description: 'Notification and messaging service',
    color: 'bg-cyan-500',
    endpoints: ['/email', '/slack', '/sms'],
  },
  'cloud-security-service': {
    name: 'Cloud Security',
    icon: Cloud,
    description: 'Multi-cloud security monitoring',
    color: 'bg-indigo-500',
    endpoints: ['/aws', '/azure', '/gcp'],
  },
  'remediation-engine': {
    name: 'Remediation Engine',
    icon: Settings,
    description: 'Automated vulnerability remediation',
    color: 'bg-yellow-500',
    endpoints: ['/fix', '/patch', '/update'],
  },
};

/**
 * Service Health Status Component
 */
const ServiceHealthStatus = ({ service, status, lastCheck }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const ServiceIcon = SERVICES[service]?.icon || Server;
  const statusConfig = {
    healthy: { color: 'bg-green-500', text: 'Healthy', textColor: 'text-green-400' },
    warning: { color: 'bg-yellow-500', text: 'Warning', textColor: 'text-yellow-400' },
    critical: { color: 'bg-red-500', text: 'Critical', textColor: 'text-red-400' },
    unknown: { color: 'bg-gray-500', text: 'Unknown', textColor: 'text-gray-400' },
  };

  const currentStatus = statusConfig[status] || statusConfig.unknown;

  return (
    <Card className={`
      transition-all duration-300 hover:scale-105 hover:shadow-lg
      ${isDark 
        ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm shadow-zinc-900/20' 
        : 'border-gray-200 bg-white/80 backdrop-blur-sm shadow-gray-200/50'
      }
    `}>
      <CardHeader className="flex flex-row items-center space-y-0 pb-2">
        <div className="flex items-center space-x-3">
          <div className={`p-2 rounded-lg ${SERVICES[service]?.color || 'bg-gray-500'}`}>
            <ServiceIcon className="h-5 w-5 text-white" />
          </div>
          <div>
            <CardTitle className={`
              text-sm font-medium transition-colors
              ${isDark ? 'text-zinc-100' : 'text-gray-900'}
            `}>
              {SERVICES[service]?.name || service}
            </CardTitle>
            <CardDescription className={`
              transition-colors
              ${isDark ? 'text-zinc-400' : 'text-gray-600'}
            `}>
              {SERVICES[service]?.description || 'Service description'}
            </CardDescription>
          </div>
        </div>
        <div className="ml-auto flex items-center space-x-2">
          <div className={`w-2 h-2 rounded-full ${currentStatus.color}`}></div>
          <Badge variant="outline" className={`
            ${currentStatus.textColor} transition-colors
            ${isDark ? 'border-zinc-600' : 'border-gray-300'}
          `}>
            {currentStatus.text}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className={`
          flex items-center justify-between text-xs transition-colors
          ${isDark ? 'text-zinc-400' : 'text-gray-600'}
        `}>
          <span>Last checked: {lastCheck}</span>
          <Button 
            variant="ghost" 
            size="sm" 
            className={`
              h-6 px-2 transition-colors
              ${isDark 
                ? 'hover:bg-zinc-800 text-zinc-400 hover:text-zinc-100' 
                : 'hover:bg-gray-100 text-gray-600 hover:text-gray-900'
              }
            `}
          >
            <RefreshCw className="h-3 w-3" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Service Performance Chart Component
 */
const ServicePerformanceChart = ({ service, timeRange = '24h' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [chartData, setChartData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate performance data - replace with real API calls
    const generateData = () => {
      const data = [];
      const now = new Date();
      const hours = timeRange === '24h' ? 24 : timeRange === '7d' ? 168 : 720;
      
      for (let i = hours; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60 * 60 * 1000);
        data.push({
          time: time.toISOString(),
          responseTime: Math.random() * 200 + 50 + (Math.sin(i / 12) * 30),
          throughput: Math.random() * 100 + 20 + (Math.cos(i / 8) * 15),
          errorRate: Math.random() * 5 + (Math.sin(i / 6) * 2),
          cpuUsage: Math.random() * 30 + 40 + (Math.sin(i / 10) * 20),
          memoryUsage: Math.random() * 20 + 60 + (Math.cos(i / 15) * 10),
        });
      }
      return data;
    };

    setLoading(true);
    setTimeout(() => {
      setChartData(generateData());
      setLoading(false);
    }, 500);
  }, [service, timeRange]);

  if (loading) {
    return (
      <Card className={`
        ${isDark 
          ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
          : 'border-gray-200 bg-white/80 backdrop-blur-sm'
        }
      `}>
        <CardHeader>
          <div className={`
            h-4 rounded w-1/3 animate-pulse
            ${isDark ? 'bg-zinc-700' : 'bg-gray-300'}
          `}></div>
        </CardHeader>
        <CardContent>
          <div className={`
            h-64 rounded animate-pulse
            ${isDark ? 'bg-zinc-700' : 'bg-gray-300'}
          `}></div>
        </CardContent>
      </Card>
    );
  }

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
          transition-colors
          ${isDark ? 'text-zinc-100' : 'text-gray-900'}
        `}>
          Performance Metrics
        </CardTitle>
        <CardDescription className={`
          transition-colors
          ${isDark ? 'text-zinc-400' : 'text-gray-600'}
        `}>
          Real-time performance data for {SERVICES[service]?.name}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="response-time" className="w-full">
          <TabsList className={`
            grid w-full grid-cols-4 transition-colors
            ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}
          `}>
            <TabsTrigger 
              value="response-time" 
              className={`
                text-xs transition-colors
                ${isDark 
                  ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
                  : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
                }
              `}
            >
              Response Time
            </TabsTrigger>
            <TabsTrigger 
              value="throughput" 
              className={`
                text-xs transition-colors
                ${isDark 
                  ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
                  : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
                }
              `}
            >
              Throughput
            </TabsTrigger>
            <TabsTrigger value="errors" className="text-xs">Error Rate</TabsTrigger>
            <TabsTrigger value="resources" className="text-xs">Resources</TabsTrigger>
          </TabsList>
          
          <TabsContent value="response-time" className="mt-4">
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="time" 
                  tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                  stroke="#9CA3AF"
                  fontSize={10}
                />
                <YAxis stroke="#9CA3AF" fontSize={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#18181b', border: '1px solid #3f3f46' }}
                  labelStyle={{ color: '#fafafa' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="responseTime" 
                  stroke="#3B82F6" 
                  fill="#3B82F6" 
                  fillOpacity={0.2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </TabsContent>
          
          <TabsContent value="throughput" className="mt-4">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="time" 
                  tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                  stroke="#9CA3AF"
                  fontSize={10}
                />
                <YAxis stroke="#9CA3AF" fontSize={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#18181b', border: '1px solid #3f3f46' }}
                  labelStyle={{ color: '#fafafa' }}
                />
                <Line 
                  type="monotone" 
                  dataKey="throughput" 
                  stroke="#10B981" 
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </TabsContent>
          
          <TabsContent value="errors" className="mt-4">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="time" 
                  tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                  stroke="#9CA3AF"
                  fontSize={10}
                />
                <YAxis stroke="#9CA3AF" fontSize={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#18181b', border: '1px solid #3f3f46' }}
                  labelStyle={{ color: '#fafafa' }}
                />
                <Bar dataKey="errorRate" fill="#EF4444" />
              </BarChart>
            </ResponsiveContainer>
          </TabsContent>
          
          <TabsContent value="resources" className="mt-4">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="time" 
                  tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                  stroke="#9CA3AF"
                  fontSize={10}
                />
                <YAxis stroke="#9CA3AF" fontSize={10} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#18181b', border: '1px solid #3f3f46' }}
                  labelStyle={{ color: '#fafafa' }}
                />
                <Line 
                  type="monotone" 
                  dataKey="cpuUsage" 
                  stroke="#F59E0B" 
                  strokeWidth={2}
                  dot={false}
                />
                <Line 
                  type="monotone" 
                  dataKey="memoryUsage" 
                  stroke="#8B5CF6" 
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

/**
 * Service Endpoint Analytics Component
 */
const ServiceEndpointAnalytics = ({ service }) => {
  const endpoints = SERVICES[service]?.endpoints || [];
  const [endpointData] = useState(() => 
    endpoints.map(endpoint => ({
      endpoint,
      requests: Math.floor(Math.random() * 10000 + 1000),
      avgResponseTime: Math.floor(Math.random() * 200 + 50),
      errorRate: Math.random() * 5,
      lastAccessed: new Date(Date.now() - Math.random() * 3600000).toLocaleTimeString(),
    }))
  );

  return (
    <Card className="border-zinc-800 bg-zinc-900/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="text-zinc-100">Endpoint Analytics</CardTitle>
        <CardDescription className="text-zinc-400">
          Performance metrics by endpoint
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {endpointData.map((endpoint, index) => (
            <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-zinc-800/50">
              <div className="flex items-center space-x-3">
                <Badge variant="outline" className="font-mono text-xs">
                  {endpoint.endpoint}
                </Badge>
                <div className="text-sm text-zinc-300">
                  {endpoint.requests.toLocaleString()} requests
                </div>
              </div>
              <div className="flex items-center space-x-4 text-xs text-zinc-400">
                <div className="flex items-center space-x-1">
                  <Clock className="h-3 w-3" />
                  <span>{endpoint.avgResponseTime}ms</span>
                </div>
                <div className="flex items-center space-x-1">
                  {endpoint.errorRate < 2 ? (
                    <CheckCircle className="h-3 w-3 text-green-400" />
                  ) : (
                    <AlertTriangle className="h-3 w-3 text-yellow-400" />
                  )}
                  <span>{endpoint.errorRate.toFixed(1)}%</span>
                </div>
                <span>{endpoint.lastAccessed}</span>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Main Service Metrics Component
 */
const ServiceMetrics = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [selectedService, setSelectedService] = useState('api-gateway');
  const [timeRange, setTimeRange] = useState('24h');
  const [serviceStatuses] = useState(() => 
    Object.keys(SERVICES).reduce((acc, service) => {
      acc[service] = {
        status: Math.random() > 0.8 ? 'warning' : 'healthy',
        lastCheck: new Date(Date.now() - Math.random() * 300000).toLocaleTimeString(),
      };
      return acc;
    }, {})
  );

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Service Selection and Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <h2 className={`
            text-2xl font-bold transition-colors
            ${isDark ? 'text-zinc-100' : 'text-gray-900'}
          `}>
            Service Metrics
          </h2>
          <Select value={selectedService} onValueChange={setSelectedService}>
            <SelectTrigger className={`
              w-64 transition-colors
              ${isDark 
                ? 'bg-zinc-800 border-zinc-700 text-zinc-100' 
                : 'bg-white border-gray-300 text-gray-900'
              }
            `}>
              <SelectValue placeholder="Select service" />
            </SelectTrigger>
            <SelectContent className={`
              transition-colors
              ${isDark 
                ? 'bg-zinc-800 border-zinc-700' 
                : 'bg-white border-gray-300'
              }
            `}>
              {Object.entries(SERVICES).map(([key, service]) => (
                <SelectItem 
                  key={key} 
                  value={key} 
                  className={isDark ? 'text-zinc-100' : 'text-gray-900'}
                >
                  <div className="flex items-center space-x-2">
                    <service.icon className="h-4 w-4" />
                    <span>{service.name}</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        
        <div className="flex items-center space-x-2">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className={`
              w-24 transition-colors
              ${isDark 
                ? 'bg-zinc-800 border-zinc-700 text-zinc-100' 
                : 'bg-white border-gray-300 text-gray-900'
              }
            `}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent className={`
              transition-colors
              ${isDark 
                ? 'bg-zinc-800 border-zinc-700' 
                : 'bg-white border-gray-300'
              }
            `}>
              <SelectItem value="24h" className={isDark ? 'text-zinc-100' : 'text-gray-900'}>
                24h
              </SelectItem>
              <SelectItem value="7d" className={isDark ? 'text-zinc-100' : 'text-gray-900'}>
                7d
              </SelectItem>
              <SelectItem value="30d" className={isDark ? 'text-zinc-100' : 'text-gray-900'}>
                30d
              </SelectItem>
            </SelectContent>
          </Select>
          <Button 
            variant="outline" 
            size="sm" 
            className={`
              transition-colors
              ${isDark 
                ? 'border-zinc-700 bg-zinc-800 text-zinc-100 hover:bg-zinc-700' 
                : 'border-gray-300 bg-white text-gray-900 hover:bg-gray-50'
              }
            `}
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Service Health Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(SERVICES).slice(0, 4).map(([serviceKey, service]) => (
          <ServiceHealthStatus
            key={serviceKey}
            service={serviceKey}
            status={serviceStatuses[serviceKey]?.status}
            lastCheck={serviceStatuses[serviceKey]?.lastCheck}
          />
        ))}
      </div>

      {/* KPI Engine Integration */}
      <KPIEngine serviceType={selectedService} />

      {/* Performance Charts and Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ServicePerformanceChart service={selectedService} timeRange={timeRange} />
        <ServiceEndpointAnalytics service={selectedService} />
      </div>
    </div>
  );
};

export default ServiceMetrics;
export { SERVICES, ServiceHealthStatus, ServicePerformanceChart }; 