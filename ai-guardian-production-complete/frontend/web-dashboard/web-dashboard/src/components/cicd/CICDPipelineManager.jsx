"use client"

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  GitBranch, 
  Zap, 
  Settings, 
  Activity, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  RefreshCw,
  Clock,
  PlayCircle,
  StopCircle,
  Terminal,
  FileCode,
  Server,
  Shield,
  Bug,
  Database,
  Archive,
  Globe,
  Webhook,
  Key,
  Users,
  History,
  TrendingUp
} from 'lucide-react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

// Mock CI/CD data
const PIPELINE_STATS = {
  total: 847,
  active: 23,
  successful: 789,
  failed: 35,
  successRate: 93.2,
  avgDuration: "12m 34s",
  securityChecks: 2347,
  vulnerabilitiesBlocked: 156
};

const PIPELINES = [
  {
    id: 'pip-001',
    name: 'AI Guardian Frontend',
    platform: 'github',
    status: 'running',
    branch: 'main',
    commit: 'feat: add trifecta manager',
    duration: '8m 23s',
    stages: [
      { name: 'Build', status: 'completed', duration: '2m 15s' },
      { name: 'Security Scan', status: 'completed', duration: '3m 45s', findings: 0 },
      { name: 'Test', status: 'running', duration: '2m 23s' },
      { name: 'Deploy', status: 'pending', duration: '' }
    ],
    lastRun: '2024-01-14T10:30:00Z',
    repository: 'OmniPanelAI/ai-guardian-frontend'
  },
  {
    id: 'pip-002',
    name: 'Code Scanner Service',
    platform: 'jenkins',
    status: 'completed',
    branch: 'develop',
    commit: 'fix: security vulnerabilities',
    duration: '15m 47s',
    stages: [
      { name: 'Build', status: 'completed', duration: '3m 20s' },
      { name: 'Security Scan', status: 'completed', duration: '6m 12s', findings: 2 },
      { name: 'Test', status: 'completed', duration: '4m 30s' },
      { name: 'Deploy', status: 'completed', duration: '1m 45s' }
    ],
    lastRun: '2024-01-14T09:15:00Z',
    repository: 'AI-Guardian/code-scanner'
  },
  {
    id: 'pip-003',
    name: 'API Gateway',
    platform: 'gitlab',
    status: 'failed',
    branch: 'feature/auth-update',
    commit: 'update: authentication flow',
    duration: '6m 12s',
    stages: [
      { name: 'Build', status: 'completed', duration: '2m 05s' },
      { name: 'Security Scan', status: 'failed', duration: '4m 07s', findings: 5 },
      { name: 'Test', status: 'cancelled', duration: '' },
      { name: 'Deploy', status: 'cancelled', duration: '' }
    ],
    lastRun: '2024-01-14T08:45:00Z',
    repository: 'ai-guardian/api-gateway'
  }
];

const SECURITY_INTEGRATIONS = [
  { name: 'SAST Integration', platform: 'SonarQube', status: 'active', pipelines: 23, findings: 45 },
  { name: 'DAST Integration', platform: 'OWASP ZAP', status: 'active', pipelines: 18, findings: 12 },
  { name: 'SCA Integration', platform: 'Snyk', status: 'active', pipelines: 31, findings: 67 },
  { name: 'Container Scanning', platform: 'Trivy', status: 'active', pipelines: 15, findings: 23 },
  { name: 'Secrets Detection', platform: 'GitLeaks', status: 'active', pipelines: 28, findings: 8 },
  { name: 'License Compliance', platform: 'FOSSA', status: 'active', pipelines: 12, findings: 3 }
];

const PIPELINE_TRENDS = [
  { date: '2024-01-08', builds: 45, success: 42, failed: 3, security: 12 },
  { date: '2024-01-09', builds: 52, success: 48, failed: 4, security: 15 },
  { date: '2024-01-10', builds: 38, success: 35, failed: 3, security: 8 },
  { date: '2024-01-11', builds: 61, success: 57, failed: 4, security: 18 },
  { date: '2024-01-12', builds: 47, success: 44, failed: 3, security: 11 },
  { date: '2024-01-13', builds: 55, success: 51, failed: 4, security: 14 },
  { date: '2024-01-14', builds: 43, success: 40, failed: 3, security: 9 }
];

const CICDPipelineManager = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');

  const getPlatformIcon = (platform) => {
    switch (platform) {
      case 'github': return '🔵';
      case 'jenkins': return '🔶';
      case 'gitlab': return '🟠';
      default: return '⚙️';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-green-400 border-green-400';
      case 'running': return 'text-blue-400 border-blue-400';
      case 'failed': return 'text-red-400 border-red-400';
      case 'pending': return 'text-yellow-400 border-yellow-400';
      case 'cancelled': return 'text-gray-400 border-gray-400';
      default: return 'text-gray-400 border-gray-400';
    }
  };

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            CI/CD Pipeline Integration
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Integrated security scanning across Jenkins, GitHub Actions, and GitLab CI
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-green-400 border-green-400">
            <CheckCircle className="w-3 h-3 mr-1" />
            {PIPELINE_STATS.successRate}% Success Rate
          </Badge>
          <Badge variant="outline" className="text-blue-400 border-blue-400">
            <Zap className="w-3 h-3 mr-1" />
            {PIPELINE_STATS.active} Active
          </Badge>
          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh All
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-5 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="pipelines">
            <GitBranch className="w-4 h-4 mr-2" />
            Pipelines
          </TabsTrigger>
          <TabsTrigger value="security">
            <Shield className="w-4 h-4 mr-2" />
            Security
          </TabsTrigger>
          <TabsTrigger value="platforms">
            <Server className="w-4 h-4 mr-2" />
            Platforms
          </TabsTrigger>
          <TabsTrigger value="analytics">
            <TrendingUp className="w-4 h-4 mr-2" />
            Analytics
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Total Pipelines', value: PIPELINE_STATS.total, icon: GitBranch, color: 'text-blue-400' },
              { title: 'Active Builds', value: PIPELINE_STATS.active, icon: PlayCircle, color: 'text-green-400' },
              { title: 'Security Checks', value: PIPELINE_STATS.securityChecks.toLocaleString(), icon: Shield, color: 'text-purple-400' },
              { title: 'Vulnerabilities Blocked', value: PIPELINE_STATS.vulnerabilitiesBlocked, icon: Bug, color: 'text-red-400' }
            ].map((stat, index) => (
              <Card key={index} className={`
                transition-all duration-300 hover:scale-105
                ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}
              `}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className={`text-sm font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {stat.title}
                  </CardTitle>
                  <stat.icon className={`h-4 w-4 ${stat.color}`} />
                </CardHeader>
                <CardContent>
                  <div className={`text-2xl font-bold ${isDark ? 'text-zinc-50' : 'text-gray-900'}`}>
                    {stat.value}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Pipeline Trends */}
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <TrendingUp className="w-5 h-5 mr-2 text-blue-400" />
                Pipeline Activity Trends (7 days)
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Build success rates and security findings over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={PIPELINE_TRENDS}>
                  <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                  <XAxis dataKey="date" stroke={isDark ? "#9CA3AF" : "#6B7280"} />
                  <YAxis stroke={isDark ? "#9CA3AF" : "#6B7280"} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: isDark ? '#18181b' : '#ffffff', 
                      border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                      borderRadius: '8px'
                    }}
                  />
                  <Area type="monotone" dataKey="builds" stackId="1" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="success" stackId="2" stroke="#10B981" fill="#10B981" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="failed" stackId="3" stroke="#EF4444" fill="#EF4444" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="security" stackId="4" stroke="#8B5CF6" fill="#8B5CF6" fillOpacity={0.3} />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Recent Pipeline Activity */}
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <History className="w-5 h-5 mr-2 text-green-400" />
                Recent Pipeline Activity
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {PIPELINES.slice(0, 3).map((pipeline) => (
                  <div key={pipeline.id} className={`
                    flex items-center justify-between p-3 rounded-lg border
                    ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div className="flex items-center space-x-3">
                      <span className="text-lg">{getPlatformIcon(pipeline.platform)}</span>
                      <div>
                        <div className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {pipeline.name}
                        </div>
                        <div className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {pipeline.branch} • {pipeline.commit.substring(0, 40)}...
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge variant="outline" className={getStatusColor(pipeline.status)}>
                        {pipeline.status}
                      </Badge>
                      <span className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        {pipeline.duration}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Pipelines Tab */}
        <TabsContent value="pipelines" className="mt-6">
          <div className="space-y-6">
            {PIPELINES.map((pipeline) => (
              <Card key={pipeline.id} className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <span className="text-xl">{getPlatformIcon(pipeline.platform)}</span>
                      <div>
                        <CardTitle className={`${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {pipeline.name}
                        </CardTitle>
                        <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {pipeline.repository} • {pipeline.branch}
                        </CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge variant="outline" className={getStatusColor(pipeline.status)}>
                        {pipeline.status}
                      </Badge>
                      <Button variant="outline" size="sm">
                        <PlayCircle className="w-4 h-4 mr-1" />
                        Run
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                      <strong>Latest Commit:</strong> {pipeline.commit} • Duration: {pipeline.duration}
                    </div>
                    
                    {/* Pipeline Stages */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      {pipeline.stages.map((stage, index) => (
                        <div key={index} className={`
                          p-3 rounded-lg border
                          ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                        `}>
                          <div className="flex items-center justify-between mb-2">
                            <span className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                              {stage.name}
                            </span>
                            {stage.status === 'completed' && <CheckCircle className="w-4 h-4 text-green-400" />}
                            {stage.status === 'running' && <PlayCircle className="w-4 h-4 text-blue-400" />}
                            {stage.status === 'failed' && <XCircle className="w-4 h-4 text-red-400" />}
                            {stage.status === 'pending' && <Clock className="w-4 h-4 text-yellow-400" />}
                            {stage.status === 'cancelled' && <StopCircle className="w-4 h-4 text-gray-400" />}
                          </div>
                          <div className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {stage.duration && `Duration: ${stage.duration}`}
                            {stage.findings !== undefined && (
                              <div className={stage.findings > 0 ? 'text-red-400' : 'text-green-400'}>
                                Security: {stage.findings} findings
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Shield className="w-5 h-5 mr-2 text-blue-400" />
                Security Integration Status
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Integrated security tools across all CI/CD platforms
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {SECURITY_INTEGRATIONS.map((integration, index) => (
                  <div key={index} className={`
                    p-4 rounded-lg border
                    ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div className="flex items-center justify-between mb-3">
                      <div>
                        <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {integration.name}
                        </h4>
                        <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {integration.platform}
                        </p>
                      </div>
                      <Badge variant="outline" className="text-green-400 border-green-400">
                        {integration.status}
                      </Badge>
                    </div>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className={`${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                          Pipelines
                        </span>
                        <span className={`${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {integration.pipelines}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className={`${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                          Findings
                        </span>
                        <span className={integration.findings > 0 ? 'text-red-400' : 'text-green-400'}>
                          {integration.findings}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Platforms Tab */}
        <TabsContent value="platforms" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              { name: 'GitHub Actions', icon: '🔵', pipelines: 15, success: 94.2, integration: 'Active' },
              { name: 'Jenkins', icon: '🔶', pipelines: 8, success: 91.5, integration: 'Active' },
              { name: 'GitLab CI', icon: '🟠', pipelines: 12, success: 96.1, integration: 'Active' }
            ].map((platform, index) => (
              <Card key={index} className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                <CardHeader>
                  <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    <span className="text-xl mr-2">{platform.icon}</span>
                    {platform.name}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className={`${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>Pipelines</span>
                      <span className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        {platform.pipelines}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className={`${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>Success Rate</span>
                      <span className={`font-semibold text-green-400`}>
                        {platform.success}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className={`${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>Integration</span>
                      <Badge variant="outline" className="text-green-400 border-green-400">
                        {platform.integration}
                      </Badge>
                    </div>
                    <Button variant="outline" className="w-full mt-4">
                      <Settings className="w-4 h-4 mr-2" />
                      Configure
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <TrendingUp className="w-5 h-5 mr-2 text-blue-400" />
                CI/CD Analytics Dashboard
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Advanced analytics for pipeline performance and security metrics
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <TrendingUp className="w-16 h-16 mx-auto text-gray-400 mb-4" />
                <h3 className={`text-lg font-semibold mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  Advanced Analytics Coming Soon
                </h3>
                <p className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Comprehensive pipeline analytics and performance insights
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default CICDPipelineManager; 