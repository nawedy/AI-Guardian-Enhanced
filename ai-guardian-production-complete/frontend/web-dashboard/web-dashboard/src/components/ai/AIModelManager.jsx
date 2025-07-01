"use client"

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Brain, 
  Activity, 
  Zap, 
  Code, 
  Shield, 
  TrendingUp, 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw, 
  Settings,
  Eye,
  Download,
  Upload,
  Play,
  Pause,
  Server,
  Cpu,
  Database,
  Network,
  BarChart3,
  LineChart,
  PieChart
} from 'lucide-react';
import { LineChart as RechartsLineChart, Line, AreaChart, Area, BarChart, Bar, PieChart as RechartsPieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

// AI Models Configuration
const AI_MODELS = {
  // Security-Focused Models
  'codet5-security': {
    name: 'CodeT5-Security',
    type: 'Transformer',
    category: 'Code Generation',
    status: 'active',
    performance: 96.2,
    accuracy: 94.8,
    latency: 125,
    memory: 2.4,
    version: 'v2.1.3',
    lastUpdated: '2024-01-15',
    specialization: 'Security vulnerability detection and code generation',
    supportedLanguages: ['Python', 'JavaScript', 'TypeScript', 'Java', 'Go'],
    trainingData: '2.3M security-focused code samples',
    deploymentStatus: 'production'
  },
  'vulngpt-pro': {
    name: 'VulnGPT-Pro',
    type: 'GPT-4 Based',
    category: 'Vulnerability Analysis',
    status: 'active',
    performance: 94.7,
    accuracy: 92.1,
    latency: 230,
    memory: 4.1,
    version: 'v1.8.2',
    lastUpdated: '2024-01-12',
    specialization: 'Advanced vulnerability pattern recognition',
    supportedLanguages: ['Python', 'JavaScript', 'C++', 'Java', 'C#'],
    trainingData: '1.8M vulnerability reports and patches',
    deploymentStatus: 'production'
  },
  'secure-llama': {
    name: 'SecureLLaMA',
    type: 'LLaMA Fine-tuned',
    category: 'Pattern Recognition',
    status: 'active',
    performance: 92.3,
    accuracy: 90.5,
    latency: 180,
    memory: 3.2,
    version: 'v1.5.1',
    lastUpdated: '2024-01-10',
    specialization: 'Security pattern identification across languages',
    supportedLanguages: ['Rust', 'Go', 'Swift', 'Kotlin', 'Dart'],
    trainingData: '1.2M multi-language security patterns',
    deploymentStatus: 'production'
  },
  'deepscan-ai': {
    name: 'DeepScan-AI',
    type: 'Custom CNN',
    category: 'Static Analysis',
    status: 'training',
    performance: 89.1,
    accuracy: 87.6,
    latency: 95,
    memory: 1.8,
    version: 'v3.0.0-beta',
    lastUpdated: '2024-01-16',
    specialization: 'Deep static code analysis and vulnerability detection',
    supportedLanguages: ['C', 'C++', 'Rust', 'Assembly'],
    trainingData: '900K static analysis reports',
    deploymentStatus: 'staging'
  },
  'autofix-bert': {
    name: 'AutoFix-BERT',
    type: 'BERT Variant',
    category: 'Context Understanding',
    status: 'active',
    performance: 91.4,
    accuracy: 89.2,
    latency: 150,
    memory: 2.1,
    version: 'v2.3.0',
    lastUpdated: '2024-01-14',
    specialization: 'Contextual code understanding and automatic fixing',
    supportedLanguages: ['TypeScript', 'JavaScript', 'Python', 'Java'],
    trainingData: '1.5M code context and fix pairs',
    deploymentStatus: 'production'
  }
};

const AIModelManager = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');

  const stats = {
    totalModels: Object.keys(AI_MODELS).length,
    activeModels: Object.values(AI_MODELS).filter(m => m.status === 'active').length,
    avgPerformance: Math.round(Object.values(AI_MODELS).reduce((sum, model) => sum + model.performance, 0) / Object.keys(AI_MODELS).length),
    totalInferences: 2847293
  };

  // Performance data for charts
  const performanceData = [
    { time: '00:00', codet5: 96, vulngpt: 95, llama: 92, deepscan: 89, bert: 91 },
    { time: '04:00', codet5: 97, vulngpt: 94, llama: 93, deepscan: 90, bert: 92 },
    { time: '08:00', codet5: 96, vulngpt: 96, llama: 92, deepscan: 91, bert: 90 },
    { time: '12:00', codet5: 98, vulngpt: 95, llama: 94, deepscan: 88, bert: 93 },
    { time: '16:00', codet5: 96, vulngpt: 93, llama: 91, deepscan: 92, bert: 91 },
    { time: '20:00', codet5: 97, vulngpt: 95, llama: 93, deepscan: 89, bert: 92 }
  ];

  const usageData = [
    { category: 'Vulnerability Detection', count: 1247, percentage: 44 },
    { category: 'Code Generation', count: 892, percentage: 31 },
    { category: 'Pattern Recognition', count: 456, percentage: 16 },
    { category: 'Auto-Remediation', count: 252, percentage: 9 }
  ];

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            AI & Machine Learning Management
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Advanced AI model management and ML pipeline orchestration
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-purple-400 border-purple-400">
            AI Enhanced
          </Badge>
          <Button variant="outline" size="sm">
            <Settings className="h-4 w-4 mr-2" />
            Configure Models
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-4 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="models">
            <Brain className="w-4 h-4 mr-2" />
            AI Models
          </TabsTrigger>
          <TabsTrigger value="performance">
            <BarChart3 className="w-4 h-4 mr-2" />
            Performance
          </TabsTrigger>
          <TabsTrigger value="pipeline">
            <Zap className="w-4 h-4 mr-2" />
            ML Pipeline
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Total AI Models', value: stats.totalModels.toString(), icon: Brain, color: 'text-purple-400' },
              { title: 'Active Models', value: stats.activeModels.toString(), icon: CheckCircle, color: 'text-green-400' },
              { title: 'Avg Performance', value: `${stats.avgPerformance}%`, icon: TrendingUp, color: 'text-blue-400' },
              { title: 'Total Inferences', value: stats.totalInferences.toLocaleString(), icon: Activity, color: 'text-orange-400' }
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

          {/* AI Usage Distribution */}
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <PieChart className="w-5 h-5 mr-2 text-blue-400" />
                AI Model Usage Distribution
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Distribution of AI model usage across different categories
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Pie Chart */}
                <ResponsiveContainer width="100%" height={300}>
                  <RechartsPieChart>
                    <Pie
                      data={usageData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={120}
                      paddingAngle={2}
                      dataKey="count"
                    >
                      {usageData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={['#3B82F6', '#10B981', '#F59E0B', '#EF4444'][index]} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#18181b' : '#ffffff', 
                        border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}
                    />
                  </RechartsPieChart>
                </ResponsiveContainer>

                {/* Usage Stats */}
                <div className="space-y-4">
                  {usageData.map((item, index) => (
                    <div key={index} className={`
                      p-3 rounded-lg border
                      ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                    `}>
                      <div className="flex items-center justify-between mb-2">
                        <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {item.category}
                        </h4>
                        <Badge variant="outline" className="text-xs">
                          {item.percentage}%
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Progress value={item.percentage} className="flex-1 h-2" />
                        <span className={`text-sm font-medium ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                          {item.count.toLocaleString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Models Tab */}
        <TabsContent value="models" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {Object.entries(AI_MODELS).map(([key, model]) => (
              <Card key={key} className={`
                transition-all duration-300 hover:scale-105
                ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}
              `}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      <Brain className="w-5 h-5 mr-2 text-purple-400" />
                      {model.name}
                    </CardTitle>
                    <Badge variant="outline" className={
                      model.status === 'active' ? 'text-green-400 border-green-400' :
                      model.status === 'training' ? 'text-orange-400 border-orange-400' :
                      'text-gray-400 border-gray-400'
                    }>
                      {model.status}
                    </Badge>
                  </div>
                  <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    {model.type} • {model.category}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Performance Metrics */}
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <div className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>Performance</div>
                        <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {model.performance}%
                        </div>
                      </div>
                      <div>
                        <div className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>Accuracy</div>
                        <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {model.accuracy}%
                        </div>
                      </div>
                    </div>

                    {/* Technical Specs */}
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Latency</span>
                        <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{model.latency}ms</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Memory</span>
                        <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{model.memory}GB</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Version</span>
                        <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{model.version}</span>
                      </div>
                    </div>

                    {/* Specialization */}
                    <div>
                      <div className={`text-xs font-medium mb-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        Specialization
                      </div>
                      <p className={`text-xs ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                        {model.specialization}
                      </p>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex space-x-2">
                      <Button variant="outline" size="sm" className="flex-1">
                        <Eye className="w-3 h-3 mr-1" />
                        Details
                      </Button>
                      <Button variant="outline" size="sm" className="flex-1">
                        <Settings className="w-3 h-3 mr-1" />
                        Configure
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Performance Tab */}
        <TabsContent value="performance" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <LineChart className="w-5 h-5 mr-2 text-green-400" />
                AI Model Performance Trends (24h)
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Real-time performance monitoring across all active AI models
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <RechartsLineChart data={performanceData}>
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
                  <Line type="monotone" dataKey="codet5" stroke="#8B5CF6" strokeWidth={2} />
                  <Line type="monotone" dataKey="vulngpt" stroke="#3B82F6" strokeWidth={2} />
                  <Line type="monotone" dataKey="llama" stroke="#10B981" strokeWidth={2} />
                  <Line type="monotone" dataKey="deepscan" stroke="#F59E0B" strokeWidth={2} />
                  <Line type="monotone" dataKey="bert" stroke="#EF4444" strokeWidth={2} />
                </RechartsLineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ML Pipeline Tab */}
        <TabsContent value="pipeline" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Zap className="w-5 h-5 mr-2 text-orange-400" />
                Machine Learning Pipeline
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Real-time ML pipeline monitoring and orchestration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {/* Pipeline Stages */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {[
                    { stage: 'Data Ingestion', status: 'active', progress: 100, latency: '2.3s', icon: Database },
                    { stage: 'Preprocessing', status: 'active', progress: 100, latency: '4.7s', icon: RefreshCw },
                    { stage: 'Feature Extraction', status: 'active', progress: 100, latency: '8.2s', icon: Brain },
                    { stage: 'Model Inference', status: 'active', progress: 100, latency: '1.9s', icon: Cpu },
                    { stage: 'Post-processing', status: 'active', progress: 100, latency: '3.1s', icon: Settings },
                    { stage: 'Result Delivery', status: 'active', progress: 100, latency: '0.8s', icon: Network }
                  ].map((stage, index) => (
                    <Card key={index} className={`
                      ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                    `}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center space-x-2">
                            <stage.icon className="w-4 h-4 text-blue-400" />
                            <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                              {stage.stage}
                            </h4>
                          </div>
                          <Badge variant="outline" className="text-green-400 border-green-400">
                            {stage.status}
                          </Badge>
                        </div>
                        <div className="space-y-2">
                          <div className="flex justify-between text-xs">
                            <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Progress</span>
                            <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{stage.progress}%</span>
                          </div>
                          <Progress value={stage.progress} className="h-2" />
                          <div className="flex justify-between text-xs">
                            <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Avg Latency</span>
                            <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{stage.latency}</span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Pipeline Metrics */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <Card className={`${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}`}>
                    <CardHeader>
                      <CardTitle className={`text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        Pipeline Performance
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        {[
                          { metric: 'Total Throughput', value: '2,847/sec', change: '+12%' },
                          { metric: 'Error Rate', value: '0.02%', change: '-45%' },
                          { metric: 'Avg Latency', value: '21.0ms', change: '-8%' },
                          { metric: 'Resource Usage', value: '67%', change: '+5%' }
                        ].map((metric, index) => (
                          <div key={index} className="flex justify-between">
                            <span className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                              {metric.metric}
                            </span>
                            <div className="text-right">
                              <span className={`text-sm font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                                {metric.value}
                              </span>
                              <span className={`text-xs ml-2 ${
                                metric.change.startsWith('+') ? 'text-green-400' : 'text-red-400'
                              }`}>
                                {metric.change}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className={`${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}`}>
                    <CardHeader>
                      <CardTitle className={`text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        Quick Actions
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-2 gap-3">
                        <Button variant="outline" size="sm" className="w-full">
                          <Play className="w-3 h-3 mr-1" />
                          Start Pipeline
                        </Button>
                        <Button variant="outline" size="sm" className="w-full">
                          <Pause className="w-3 h-3 mr-1" />
                          Pause Pipeline
                        </Button>
                        <Button variant="outline" size="sm" className="w-full">
                          <RefreshCw className="w-3 h-3 mr-1" />
                          Restart
                        </Button>
                        <Button variant="outline" size="sm" className="w-full">
                          <Settings className="w-3 h-3 mr-1" />
                          Configure
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AIModelManager; 