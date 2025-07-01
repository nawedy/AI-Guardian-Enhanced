"use client"

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { 
  FileCode,
  AlertTriangle,
  CheckCircle,
  Bug,
  Shield,
  Clock,
  GitCommit,
  FileText,
  Zap,
  TrendingUp,
  Search,
  Filter,
  Download,
  RefreshCw,
  Code,
  Target,
  Activity,
  BarChart3,
  PieChart,
  Lock,
  Unlock,
  Eye,
  ChevronRight,
  ChevronDown,
  ExternalLink,
  Settings
} from 'lucide-react';
import { LineChart, Line, PieChart as RechartsPieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

// Mock detailed scan results
const SCAN_RESULTS = {
  projectId: 'proj_001',
  projectName: 'ai-guardian-core',
  scanId: 'scan_001',
  status: 'completed',
  startTime: '2024-01-15T10:30:00Z',
  endTime: '2024-01-15T10:32:34Z',
  duration: '2m 34s',
  scannedFiles: 156,
  totalLines: 45789,
  
  summary: {
    codeQuality: 87.5,
    security: 78.2,
    maintainability: 82.6,
    reliability: 85.1,
    coverage: 89.3,
    duplicates: 3.2,
    technicalDebt: '4h 23m'
  },
  
  vulnerabilities: {
    critical: 2,
    high: 5,
    medium: 12,
    low: 8,
    info: 18,
    fixed: 28,
    total: 45
  },
  
  languages: [
    { name: 'Python', files: 89, lines: 32456, percentage: 71 },
    { name: 'JavaScript', files: 34, lines: 8923, percentage: 19 },
    { name: 'TypeScript', files: 18, lines: 3234, percentage: 7 },
    { name: 'JSON', files: 15, lines: 1176, percentage: 3 }
  ],
  
  topIssues: [
    {
      id: 'issue_001',
      severity: 'critical',
      type: 'SQL Injection',
      file: 'src/database/queries.py',
      line: 127,
      description: 'Potential SQL injection vulnerability detected',
      rule: 'security/sql-injection',
      impact: 'High',
      effort: 'Medium',
      autoFixable: true
    },
    {
      id: 'issue_002',
      severity: 'critical',
      type: 'XSS Vulnerability',
      file: 'src/api/routes.py',
      line: 89,
      description: 'Cross-site scripting vulnerability in user input handling',
      rule: 'security/xss',
      impact: 'High',
      effort: 'Low',
      autoFixable: true
    },
    {
      id: 'issue_003',
      severity: 'high',
      type: 'Weak Cryptography',
      file: 'src/auth/encryption.py',
      line: 45,
      description: 'Use of weak cryptographic algorithm MD5',
      rule: 'security/weak-crypto',
      impact: 'Medium',
      effort: 'Medium',
      autoFixable: false
    }
  ],
  
  fileStats: [
    { file: 'src/database/queries.py', issues: 8, complexity: 'High', coverage: 67, size: '2.3KB' },
    { file: 'src/api/routes.py', issues: 6, complexity: 'Medium', coverage: 89, size: '4.1KB' },
    { file: 'src/auth/encryption.py', issues: 5, complexity: 'Medium', coverage: 78, size: '1.8KB' },
    { file: 'src/models/user.py', issues: 3, complexity: 'Low', coverage: 95, size: '3.2KB' },
    { file: 'src/utils/helpers.py', issues: 2, complexity: 'Low', coverage: 92, size: '1.5KB' }
  ]
};

// Trend data for charts
const VULNERABILITY_TRENDS = [
  { date: '2024-01-08', critical: 4, high: 8, medium: 15, low: 12 },
  { date: '2024-01-09', critical: 3, high: 7, medium: 13, low: 10 },
  { date: '2024-01-10', critical: 3, high: 6, medium: 12, low: 9 },
  { date: '2024-01-11', critical: 2, high: 5, medium: 11, low: 8 },
  { date: '2024-01-12', critical: 2, high: 5, medium: 12, low: 8 },
  { date: '2024-01-13', critical: 2, high: 5, medium: 12, low: 8 },
  { date: '2024-01-14', critical: 2, high: 5, medium: 12, low: 8 }
];

const COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6',
  info: '#6B7280'
};

const RepoScanner = ({ projectId, className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedIssues, setExpandedIssues] = useState(new Set());

  const filteredIssues = SCAN_RESULTS.topIssues.filter(issue => {
    const matchesSeverity = selectedSeverity === 'all' || issue.severity === selectedSeverity;
    const matchesSearch = issue.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         issue.file.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const toggleIssueExpanded = (issueId) => {
    const newExpanded = new Set(expandedIssues);
    if (newExpanded.has(issueId)) {
      newExpanded.delete(issueId);
    } else {
      newExpanded.add(issueId);
    }
    setExpandedIssues(newExpanded);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400 border-red-400';
      case 'high': return 'text-orange-400 border-orange-400';
      case 'medium': return 'text-yellow-400 border-yellow-400';
      case 'low': return 'text-blue-400 border-blue-400';
      default: return 'text-gray-400 border-gray-400';
    }
  };

  const vulnerabilityPieData = [
    { name: 'Critical', value: SCAN_RESULTS.vulnerabilities.critical, color: COLORS.critical },
    { name: 'High', value: SCAN_RESULTS.vulnerabilities.high, color: COLORS.high },
    { name: 'Medium', value: SCAN_RESULTS.vulnerabilities.medium, color: COLORS.medium },
    { name: 'Low', value: SCAN_RESULTS.vulnerabilities.low, color: COLORS.low }
  ];

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Repository Scan Results
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Detailed analysis for {SCAN_RESULTS.projectName} - Scan ID: {SCAN_RESULTS.scanId}
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-green-400 border-green-400">
            Scan Complete
          </Badge>
          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Re-scan
          </Button>
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-5 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview">
            <BarChart3 className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="vulnerabilities">
            <Shield className="w-4 h-4 mr-2" />
            Vulnerabilities
          </TabsTrigger>
          <TabsTrigger value="files">
            <FileCode className="w-4 h-4 mr-2" />
            File Analysis
          </TabsTrigger>
          <TabsTrigger value="trends">
            <TrendingUp className="w-4 h-4 mr-2" />
            Trends
          </TabsTrigger>
          <TabsTrigger value="details">
            <Eye className="w-4 h-4 mr-2" />
            Scan Details
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Overall Score', value: `${SCAN_RESULTS.summary.codeQuality}%`, icon: Target, color: 'text-green-400' },
              { title: 'Security Score', value: `${SCAN_RESULTS.summary.security}%`, icon: Shield, color: 'text-orange-400' },
              { title: 'Total Issues', value: SCAN_RESULTS.vulnerabilities.total.toString(), icon: Bug, color: 'text-red-400' },
              { title: 'Code Coverage', value: `${SCAN_RESULTS.summary.coverage}%`, icon: Activity, color: 'text-blue-400' }
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

          {/* Quality Metrics and Vulnerabilities */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Quality Metrics */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <BarChart3 className="w-5 h-5 mr-2 text-blue-400" />
                  Quality Metrics
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { label: 'Code Quality', value: SCAN_RESULTS.summary.codeQuality },
                    { label: 'Security', value: SCAN_RESULTS.summary.security },
                    { label: 'Maintainability', value: SCAN_RESULTS.summary.maintainability },
                    { label: 'Reliability', value: SCAN_RESULTS.summary.reliability },
                    { label: 'Coverage', value: SCAN_RESULTS.summary.coverage }
                  ].map((metric, index) => (
                    <div key={index} className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>
                          {metric.label}
                        </span>
                        <span className="font-medium">
                          {metric.value}%
                        </span>
                      </div>
                      <Progress value={metric.value} className="h-2" />
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Vulnerability Distribution */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <PieChart className="w-5 h-5 mr-2 text-red-400" />
                  Vulnerability Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <RechartsPieChart>
                    <Pie
                      data={vulnerabilityPieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      fill="#8884d8"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {vulnerabilityPieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </RechartsPieChart>
                </ResponsiveContainer>
                <div className="grid grid-cols-2 gap-4 mt-4">
                  {vulnerabilityPieData.map((item, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      <div 
                        className="w-3 h-3 rounded-full" 
                        style={{ backgroundColor: item.color }}
                      ></div>
                      <span className={`text-sm ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                        {item.name}: {item.value}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Language Distribution */}
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Code className="w-5 h-5 mr-2 text-purple-400" />
                Language Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {SCAN_RESULTS.languages.map((lang, index) => (
                  <div key={index} className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>
                        {lang.name} ({lang.files} files)
                      </span>
                      <span className="font-medium">
                        {lang.percentage}% ({lang.lines.toLocaleString()} lines)
                      </span>
                    </div>
                    <Progress value={lang.percentage} className="h-2" />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vulnerabilities Tab */}
        <TabsContent value="vulnerabilities" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Shield className="w-5 h-5 mr-2 text-red-400" />
                Security Vulnerabilities
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Detailed analysis of security issues found in your codebase
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Filters */}
              <div className="flex items-center space-x-4 mb-6">
                <div className="flex-1">
                  <Input
                    placeholder="Search vulnerabilities..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className={isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white'}
                  />
                </div>
                <select
                  value={selectedSeverity}
                  onChange={(e) => setSelectedSeverity(e.target.value)}
                  className={`px-3 py-2 rounded-md border ${
                    isDark ? 'bg-zinc-800 border-zinc-700 text-zinc-100' : 'bg-white border-gray-300'
                  }`}
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              {/* Vulnerability List */}
              <div className="space-y-4">
                {filteredIssues.map((issue) => (
                  <div key={issue.id} className={`
                    border rounded-lg overflow-hidden
                    ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div 
                      className="p-4 cursor-pointer hover:bg-opacity-80"
                      onClick={() => toggleIssueExpanded(issue.id)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          {expandedIssues.has(issue.id) ? (
                            <ChevronDown className="w-4 h-4 text-gray-400" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-gray-400" />
                          )}
                          <Badge variant="outline" className={getSeverityColor(issue.severity)}>
                            {issue.severity.toUpperCase()}
                          </Badge>
                          <div>
                            <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                              {issue.type}
                            </h4>
                            <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                              {issue.file}:{issue.line}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          {issue.autoFixable && (
                            <Badge variant="outline" className="text-green-400 border-green-400">
                              <Zap className="w-3 h-3 mr-1" />
                              Auto-fixable
                            </Badge>
                          )}
                          <Button variant="outline" size="sm">
                            <ExternalLink className="w-3 h-3 mr-1" />
                            View
                          </Button>
                        </div>
                      </div>
                      
                      {expandedIssues.has(issue.id) && (
                        <div className="mt-4 pt-4 border-t border-zinc-700">
                          <p className={`mb-4 ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                            {issue.description}
                          </p>
                          <div className="grid grid-cols-3 gap-4 text-sm">
                            <div>
                              <span className={`font-medium ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                Impact:
                              </span>
                              <span className={`ml-2 ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                                {issue.impact}
                              </span>
                            </div>
                            <div>
                              <span className={`font-medium ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                Effort:
                              </span>
                              <span className={`ml-2 ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                                {issue.effort}
                              </span>
                            </div>
                            <div>
                              <span className={`font-medium ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                Rule:
                              </span>
                              <span className={`ml-2 ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                                {issue.rule}
                              </span>
                            </div>
                          </div>
                          <div className="flex space-x-2 mt-4">
                            <Button size="sm">
                              Fix Now
                            </Button>
                            <Button variant="outline" size="sm">
                              Mark as False Positive
                            </Button>
                            <Button variant="outline" size="sm">
                              Create Issue
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Files Tab */}
        <TabsContent value="files" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <FileCode className="w-5 h-5 mr-2 text-blue-400" />
                File Analysis
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Detailed analysis of individual files and their security status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {SCAN_RESULTS.fileStats.map((file, index) => (
                  <div key={index} className={`
                    p-4 rounded-lg border
                    ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <FileText className="w-5 h-5 text-blue-400" />
                        <div>
                          <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {file.file}
                          </h4>
                          <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {file.size} • {file.issues} issues • {file.coverage}% coverage
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant="outline" className={
                          file.complexity === 'High' ? 'text-red-400 border-red-400' :
                          file.complexity === 'Medium' ? 'text-yellow-400 border-yellow-400' :
                          'text-green-400 border-green-400'
                        }>
                          {file.complexity} Complexity
                        </Badge>
                        <Button variant="outline" size="sm">
                          <Eye className="w-3 h-3 mr-1" />
                          View
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Trends Tab */}
        <TabsContent value="trends" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <TrendingUp className="w-5 h-5 mr-2 text-green-400" />
                Security Trends (7 days)
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Historical vulnerability trends and improvements over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <LineChart data={VULNERABILITY_TRENDS}>
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
                  <Line type="monotone" dataKey="critical" stroke={COLORS.critical} strokeWidth={2} />
                  <Line type="monotone" dataKey="high" stroke={COLORS.high} strokeWidth={2} />
                  <Line type="monotone" dataKey="medium" stroke={COLORS.medium} strokeWidth={2} />
                  <Line type="monotone" dataKey="low" stroke={COLORS.low} strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Scan Details Tab */}
        <TabsContent value="details" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Settings className="w-5 h-5 mr-2 text-gray-400" />
                Scan Configuration & Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    Scan Information
                  </h4>
                  <div className="space-y-3">
                    {[
                      { label: 'Scan ID', value: SCAN_RESULTS.scanId },
                      { label: 'Start Time', value: new Date(SCAN_RESULTS.startTime).toLocaleString() },
                      { label: 'End Time', value: new Date(SCAN_RESULTS.endTime).toLocaleString() },
                      { label: 'Duration', value: SCAN_RESULTS.duration },
                      { label: 'Files Scanned', value: SCAN_RESULTS.scannedFiles.toString() },
                      { label: 'Total Lines', value: SCAN_RESULTS.totalLines.toLocaleString() }
                    ].map((item, index) => (
                      <div key={index} className="flex justify-between">
                        <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {item.label}:
                        </span>
                        <span className={`font-medium ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                          {item.value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    Scan Configuration
                  </h4>
                  <div className="space-y-3">
                    {[
                      { label: 'Security Rules', value: '247 active' },
                      { label: 'Quality Rules', value: '189 active' },
                      { label: 'Custom Rules', value: '23 active' },
                      { label: 'Exclusions', value: '12 patterns' },
                      { label: 'AI Analysis', value: 'Enabled' },
                      { label: 'Auto-fix', value: 'Enabled' }
                    ].map((item, index) => (
                      <div key={index} className="flex justify-between">
                        <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {item.label}:
                        </span>
                        <span className={`font-medium ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                          {item.value}
                        </span>
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

export default RepoScanner; 