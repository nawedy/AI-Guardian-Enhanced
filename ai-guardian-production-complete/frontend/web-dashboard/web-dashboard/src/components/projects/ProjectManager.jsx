"use client"

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { 
  GitBranch,
  Github,
  FolderOpen,
  Scan,
  Activity,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Eye,
  Settings,
  Plus,
  Trash2,
  Pause,
  Play,
  RefreshCw,
  Download,
  Upload,
  Code,
  FileCode,
  Zap,
  TrendingUp,
  Globe,
  Lock,
  Unlock,
  Star,
  Git,
  Folder,
  Monitor
} from 'lucide-react';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

// Mock project data
const CONNECTED_PROJECTS = [
  {
    id: 'proj_001',
    name: 'ai-guardian-core',
    type: 'github',
    source: 'https://github.com/company/ai-guardian-core',
    status: 'active',
    lastScan: '2024-01-15T10:30:00Z',
    nextScan: '2024-01-15T22:30:00Z',
    branch: 'main',
    language: 'Python',
    vulnerabilities: { critical: 2, high: 5, medium: 12, low: 8 },
    codeQuality: 87.5,
    coverage: 89,
    commits: 247,
    contributors: 8,
    size: '2.3 MB',
    files: 156,
    scanDuration: '2m 34s',
    isPrivate: true,
    webhook: true,
    monitoring: true
  },
  {
    id: 'proj_002',
    name: 'frontend-dashboard',
    type: 'github',
    source: 'https://github.com/company/frontend-dashboard',
    status: 'scanning',
    lastScan: '2024-01-15T09:15:00Z',
    nextScan: null,
    branch: 'development',
    language: 'JavaScript',
    vulnerabilities: { critical: 0, high: 3, medium: 8, low: 15 },
    codeQuality: 92.1,
    coverage: 78,
    commits: 189,
    contributors: 5,
    size: '1.8 MB',
    files: 234,
    scanDuration: '1m 56s',
    isPrivate: false,
    webhook: true,
    monitoring: true,
    progress: 67
  },
  {
    id: 'proj_003',
    name: 'local-api-service',
    type: 'local',
    source: '/Users/dev/projects/api-service',
    status: 'active',
    lastScan: '2024-01-15T11:45:00Z',
    nextScan: '2024-01-15T23:45:00Z',
    branch: null,
    language: 'TypeScript',
    vulnerabilities: { critical: 1, high: 2, medium: 6, low: 12 },
    codeQuality: 85.2,
    coverage: 82,
    commits: null,
    contributors: null,
    size: '3.1 MB',
    files: 289,
    scanDuration: '3m 12s',
    isPrivate: true,
    webhook: false,
    monitoring: true
  }
];

// Scanning activity data
const SCAN_ACTIVITY = [
  { time: '00:00', scans: 12, vulnerabilities: 45, fixes: 38 },
  { time: '04:00', scans: 8, vulnerabilities: 32, fixes: 28 },
  { time: '08:00', scans: 15, vulnerabilities: 28, fixes: 35 },
  { time: '12:00', scans: 22, vulnerabilities: 18, fixes: 42 },
  { time: '16:00', scans: 18, vulnerabilities: 25, fixes: 38 },
  { time: '20:00', scans: 14, vulnerabilities: 31, fixes: 29 }
];

const ProjectManager = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');
  const [projects, setProjects] = useState(CONNECTED_PROJECTS);
  const [showGitHubConnect, setShowGitHubConnect] = useState(false);
  const [showLocalConnect, setShowLocalConnect] = useState(false);
  const [githubUrl, setGitHubUrl] = useState('');
  const [localPath, setLocalPath] = useState('');

  const stats = {
    totalProjects: projects.length,
    activeScanning: projects.filter(p => p.status === 'scanning').length,
    totalVulnerabilities: projects.reduce((sum, p) => sum + Object.values(p.vulnerabilities).reduce((a, b) => a + b, 0), 0),
    avgCodeQuality: Math.round(projects.reduce((sum, p) => sum + p.codeQuality, 0) / projects.length)
  };

  const connectGitHubRepo = () => {
    if (!githubUrl) return;
    
    // Simulate GitHub OAuth and repo connection
    const newProject = {
      id: `proj_${Date.now()}`,
      name: githubUrl.split('/').pop(),
      type: 'github',
      source: githubUrl,
      status: 'connecting',
      branch: 'main',
      language: 'Unknown',
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      codeQuality: 0,
      coverage: 0,
      isPrivate: true,
      webhook: false,
      monitoring: false
    };
    
    setProjects([...projects, newProject]);
    setGitHubUrl('');
    setShowGitHubConnect(false);
  };

  const connectLocalProject = () => {
    if (!localPath) return;
    
    const newProject = {
      id: `proj_${Date.now()}`,
      name: localPath.split('/').pop(),
      type: 'local',
      source: localPath,
      status: 'scanning',
      branch: null,
      language: 'Unknown',
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      codeQuality: 0,
      coverage: 0,
      isPrivate: true,
      webhook: false,
      monitoring: false,
      progress: 0
    };
    
    setProjects([...projects, newProject]);
    setLocalPath('');
    setShowLocalConnect(false);
  };

  const toggleMonitoring = (projectId) => {
    setProjects(projects.map(p => 
      p.id === projectId ? { ...p, monitoring: !p.monitoring } : p
    ));
  };

  const removeProject = (projectId) => {
    setProjects(projects.filter(p => p.id !== projectId));
  };

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Project Integration & Monitoring
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Connect GitHub repositories and local projects for continuous security scanning
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-green-400 border-green-400">
            Active Monitoring
          </Badge>
          <Button 
            variant="outline" 
            size="sm"
            onClick={() => setShowGitHubConnect(true)}
          >
            <Github className="h-4 w-4 mr-2" />
            Connect GitHub
          </Button>
          <Button 
            variant="outline" 
            size="sm"
            onClick={() => setShowLocalConnect(true)}
          >
            <FolderOpen className="h-4 w-4 mr-2" />
            Add Local Project
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-4 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="projects">
            <GitBranch className="w-4 h-4 mr-2" />
            Connected Projects
          </TabsTrigger>
          <TabsTrigger value="scanning">
            <Scan className="w-4 h-4 mr-2" />
            Active Scanning
          </TabsTrigger>
          <TabsTrigger value="monitoring">
            <Monitor className="w-4 h-4 mr-2" />
            Real-time Monitoring
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Connected Projects', value: stats.totalProjects.toString(), icon: GitBranch, color: 'text-blue-400' },
              { title: 'Active Scans', value: stats.activeScanning.toString(), icon: Scan, color: 'text-orange-400' },
              { title: 'Total Vulnerabilities', value: stats.totalVulnerabilities.toString(), icon: Shield, color: 'text-red-400' },
              { title: 'Avg Code Quality', value: `${stats.avgCodeQuality}%`, icon: TrendingUp, color: 'text-green-400' }
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

          {/* Scanning Activity Chart */}
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Activity className="w-5 h-5 mr-2 text-green-400" />
                Scanning Activity (24h)
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Real-time scanning activity and vulnerability trends
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={SCAN_ACTIVITY}>
                  <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                  <XAxis dataKey="time" stroke={isDark ? "#9CA3AF" : "#6B7280"} />
                  <YAxis stroke={isDark ? "#9CA3AF" : "#6B7280"} />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: isDark ? '#18181b' : '#ffffff', 
                      border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                      borderRadius: '8px'
                    }}
                  />
                  <Area type="monotone" dataKey="scans" stackId="1" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="vulnerabilities" stackId="2" stroke="#EF4444" fill="#EF4444" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="fixes" stackId="3" stroke="#10B981" fill="#10B981" fillOpacity={0.3} />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* GitHub Integration */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Github className="w-5 h-5 mr-2 text-purple-400" />
                  GitHub Integration
                </CardTitle>
                <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Connect your GitHub repositories for automated scanning
                </CardDescription>
              </CardHeader>
              <CardContent>
                {showGitHubConnect ? (
                  <div className="space-y-4">
                    <Input
                      placeholder="https://github.com/username/repository"
                      value={githubUrl}
                      onChange={(e) => setGitHubUrl(e.target.value)}
                      className={isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white'}
                    />
                    <div className="flex space-x-2">
                      <Button onClick={connectGitHubRepo} className="flex-1">
                        <Plus className="w-4 h-4 mr-2" />
                        Connect Repository
                      </Button>
                      <Button 
                        variant="outline" 
                        onClick={() => setShowGitHubConnect(false)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <p className={`text-sm ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                      Automatically scan your GitHub repositories with webhooks for real-time monitoring.
                    </p>
                    <div className="flex space-x-2">
                      <Button 
                        onClick={() => setShowGitHubConnect(true)}
                        className="flex-1"
                      >
                        <Github className="w-4 h-4 mr-2" />
                        Add Repository
                      </Button>
                      <Button variant="outline">
                        <Settings className="w-4 h-4 mr-2" />
                        Configure OAuth
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Local Project Integration */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <FolderOpen className="w-5 h-5 mr-2 text-blue-400" />
                  Local Project Scanning
                </CardTitle>
                <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Scan local project directories for security vulnerabilities
                </CardDescription>
              </CardHeader>
              <CardContent>
                {showLocalConnect ? (
                  <div className="space-y-4">
                    <Input
                      placeholder="/path/to/your/project"
                      value={localPath}
                      onChange={(e) => setLocalPath(e.target.value)}
                      className={isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white'}
                    />
                    <div className="flex space-x-2">
                      <Button onClick={connectLocalProject} className="flex-1">
                        <Plus className="w-4 h-4 mr-2" />
                        Add Project
                      </Button>
                      <Button 
                        variant="outline" 
                        onClick={() => setShowLocalConnect(false)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <p className={`text-sm ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                      Scan local project directories with file system monitoring for real-time analysis.
                    </p>
                    <div className="flex space-x-2">
                      <Button 
                        onClick={() => setShowLocalConnect(true)}
                        className="flex-1"
                      >
                        <FolderOpen className="w-4 h-4 mr-2" />
                        Browse Directory
                      </Button>
                      <Button variant="outline">
                        <Upload className="w-4 h-4 mr-2" />
                        Upload Archive
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Connected Projects Tab */}
        <TabsContent value="projects" className="mt-6">
          <div className="space-y-4">
            {projects.map((project) => (
              <Card key={project.id} className={`
                transition-all duration-300 hover:scale-[1.01]
                ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}
              `}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {project.type === 'github' ? (
                        <Github className="w-6 h-6 text-purple-400" />
                      ) : (
                        <Folder className="w-6 h-6 text-blue-400" />
                      )}
                      <div>
                        <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {project.name}
                          {project.isPrivate && <Lock className="w-4 h-4 ml-2 text-gray-400" />}
                        </CardTitle>
                        <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {project.source}
                        </CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge variant="outline" className={
                        project.status === 'active' ? 'text-green-400 border-green-400' :
                        project.status === 'scanning' ? 'text-orange-400 border-orange-400' :
                        project.status === 'connecting' ? 'text-blue-400 border-blue-400' :
                        'text-gray-400 border-gray-400'
                      }>
                        {project.status}
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        {project.language}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Project Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className={`p-3 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                        <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {project.codeQuality}%
                        </div>
                        <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Code Quality
                        </div>
                      </div>
                      <div className={`p-3 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                        <div className={`text-lg font-bold text-red-400`}>
                          {Object.values(project.vulnerabilities).reduce((a, b) => a + b, 0)}
                        </div>
                        <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Vulnerabilities
                        </div>
                      </div>
                      <div className={`p-3 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                        <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {project.files}
                        </div>
                        <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Files
                        </div>
                      </div>
                      <div className={`p-3 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                        <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {project.size}
                        </div>
                        <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Size
                        </div>
                      </div>
                    </div>

                    {/* Scanning Progress */}
                    {project.status === 'scanning' && project.progress && (
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>
                            Scanning in progress...
                          </span>
                          <span className="text-orange-400">{project.progress}%</span>
                        </div>
                        <Progress value={project.progress} className="h-2" />
                      </div>
                    )}

                    {/* Vulnerability Breakdown */}
                    <div className="grid grid-cols-4 gap-2">
                      {[
                        { level: 'Critical', count: project.vulnerabilities.critical, color: 'text-red-400' },
                        { level: 'High', count: project.vulnerabilities.high, color: 'text-orange-400' },
                        { level: 'Medium', count: project.vulnerabilities.medium, color: 'text-yellow-400' },
                        { level: 'Low', count: project.vulnerabilities.low, color: 'text-blue-400' }
                      ].map((vuln, index) => (
                        <div key={index} className="text-center">
                          <div className={`text-lg font-bold ${vuln.color}`}>
                            {vuln.count}
                          </div>
                          <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {vuln.level}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Project Actions */}
                    <div className="flex items-center justify-between pt-4 border-t border-zinc-700">
                      <div className="flex space-x-2">
                        <Button variant="outline" size="sm">
                          <Scan className="w-3 h-3 mr-1" />
                          Scan Now
                        </Button>
                        <Button variant="outline" size="sm">
                          <Eye className="w-3 h-3 mr-1" />
                          View Report
                        </Button>
                        <Button variant="outline" size="sm">
                          <Settings className="w-3 h-3 mr-1" />
                          Configure
                        </Button>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => toggleMonitoring(project.id)}
                        >
                          {project.monitoring ? (
                            <>
                              <Pause className="w-3 h-3 mr-1" />
                              Disable Monitoring
                            </>
                          ) : (
                            <>
                              <Play className="w-3 h-3 mr-1" />
                              Enable Monitoring
                            </>
                          )}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => removeProject(project.id)}
                        >
                          <Trash2 className="w-3 h-3 mr-1" />
                          Remove
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Active Scanning Tab */}
        <TabsContent value="scanning" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Scan className="w-5 h-5 mr-2 text-orange-400" />
                Active Scanning Queue
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Real-time scanning progress and queue management
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {projects.filter(p => p.status === 'scanning').map((project) => (
                  <div key={project.id} className={`
                    p-4 rounded-lg border
                    ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <RefreshCw className="w-5 h-5 animate-spin text-orange-400" />
                        <div>
                          <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {project.name}
                          </h4>
                          <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {project.type === 'github' ? 'GitHub Repository' : 'Local Project'}
                          </p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-orange-400 border-orange-400">
                        Scanning...
                      </Badge>
                    </div>
                    
                    {project.progress && (
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>
                            Progress
                          </span>
                          <span className="text-orange-400">{project.progress}%</span>
                        </div>
                        <Progress value={project.progress} className="h-2" />
                      </div>
                    )}
                  </div>
                ))}
                
                {projects.filter(p => p.status === 'scanning').length === 0 && (
                  <div className="text-center py-8">
                    <Scan className="w-8 h-8 mx-auto text-gray-400 mb-4" />
                    <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                      No active scans. Start a scan from the Connected Projects tab.
                    </p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Real-time Monitoring Tab */}
        <TabsContent value="monitoring" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Monitor className="w-5 h-5 mr-2 text-green-400" />
                Real-time Project Monitoring
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Continuous monitoring and automated security alerts
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {/* Monitoring Stats */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {[
                    { label: 'Projects Monitored', value: projects.filter(p => p.monitoring).length, icon: Activity },
                    { label: 'Active Webhooks', value: projects.filter(p => p.webhook).length, icon: Globe },
                    { label: 'Alerts Today', value: 23, icon: AlertTriangle }
                  ].map((stat, index) => (
                    <div key={index} className={`p-4 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                      <div className="flex items-center space-x-3">
                        <stat.icon className="w-5 h-5 text-blue-400" />
                        <div>
                          <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {stat.value}
                          </div>
                          <div className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {stat.label}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Monitored Projects */}
                <div>
                  <h4 className={`font-semibold mb-4 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    Monitored Projects
                  </h4>
                  <div className="space-y-3">
                    {projects.filter(p => p.monitoring).map((project) => (
                      <div key={project.id} className={`
                        p-3 rounded-lg border flex items-center justify-between
                        ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                      `}>
                        <div className="flex items-center space-x-3">
                          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                          <div>
                            <h5 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                              {project.name}
                            </h5>
                            <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                              Last scan: {new Date(project.lastScan).toLocaleTimeString()}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          {project.webhook && (
                            <Badge variant="outline" className="text-green-400 border-green-400">
                              Webhook Active
                            </Badge>
                          )}
                          <Badge variant="outline" className="text-blue-400 border-blue-400">
                            Monitoring
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ProjectManager; 