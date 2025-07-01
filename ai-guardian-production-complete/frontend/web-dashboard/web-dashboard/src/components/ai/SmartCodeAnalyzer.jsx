"use client"

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { Progress } from '@/components/ui/progress';
import { 
  Code2,
  Scan,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Brain,
  Lightbulb,
  FileCode,
  Bug,
  Zap,
  Target,
  TrendingUp,
  Clock,
  Eye,
  RefreshCw,
  Upload,
  Download,
  Play,
  GitBranch,
  Terminal,
  Search
} from 'lucide-react';
import { AreaChart, Area, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

// Mock analysis results
const ANALYSIS_RESULTS = {
  vulnerability: {
    critical: 3,
    high: 12,
    medium: 27,
    low: 45,
    info: 18
  },
  codeQuality: {
    score: 87.5,
    maintainability: 82,
    complexity: 76,
    duplication: 91,
    coverage: 89
  },
  aiInsights: [
    {
      type: 'security',
      severity: 'high',
      title: 'SQL Injection Vulnerability',
      description: 'Detected potential SQL injection in user input handling',
      file: 'src/auth/login.py',
      line: 47,
      confidence: 94,
      suggestion: 'Use parameterized queries or ORM methods to prevent SQL injection',
      aiModel: 'VulnGPT-Pro'
    },
    {
      type: 'performance',
      severity: 'medium',
      title: 'Inefficient Database Query',
      description: 'N+1 query pattern detected in user data retrieval',
      file: 'src/models/user.js',
      line: 23,
      confidence: 87,
      suggestion: 'Implement eager loading or join queries to reduce database calls',
      aiModel: 'CodeT5-Security'
    },
    {
      type: 'code_quality',
      severity: 'low',
      title: 'Code Duplication',
      description: 'Similar code patterns found across multiple files',
      file: 'src/utils/validation.py',
      line: 15,
      confidence: 78,
      suggestion: 'Extract common validation logic into reusable utility functions',
      aiModel: 'AutoFix-BERT'
    }
  ]
};

const SmartCodeAnalyzer = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('analyzer');
  const [analysisCode, setAnalysisCode] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResults, setAnalysisResults] = useState(null);

  const performAnalysis = () => {
    setIsAnalyzing(true);
    // Simulate AI analysis
    setTimeout(() => {
      setAnalysisResults(ANALYSIS_RESULTS);
      setIsAnalyzing(false);
    }, 3000);
  };

  // Sample code for demo
  const sampleCode = `def authenticate_user(username, password):
    # Vulnerable SQL query - potential injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    
    # Inefficient password hashing
    if hashlib.md5(password.encode()).hexdigest() == user_hash:
        return True
    return False

# Missing input validation
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if authenticate_user(username, password):
        session['user'] = username
        return redirect('/dashboard')
    return render_template('login.html', error='Invalid credentials')`;

  const trendsData = [
    { date: '2024-01-01', vulnerabilities: 45, fixes: 38, score: 78 },
    { date: '2024-01-02', vulnerabilities: 42, fixes: 41, score: 81 },
    { date: '2024-01-03', vulnerabilities: 38, fixes: 39, score: 84 },
    { date: '2024-01-04', vulnerabilities: 35, fixes: 42, score: 87 },
    { date: '2024-01-05', vulnerabilities: 32, fixes: 45, score: 89 },
    { date: '2024-01-06', vulnerabilities: 28, fixes: 48, score: 92 },
    { date: '2024-01-07', vulnerabilities: 25, fixes: 52, score: 94 }
  ];

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Smart Code Analyzer
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            AI-powered code analysis, vulnerability detection, and intelligent insights
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-blue-400 border-blue-400">
            AI Powered
          </Badge>
          <Button variant="outline" size="sm">
            <Upload className="h-4 w-4 mr-2" />
            Upload Project
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-4 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="analyzer">
            <Scan className="w-4 h-4 mr-2" />
            Code Analyzer
          </TabsTrigger>
          <TabsTrigger value="insights">
            <Brain className="w-4 h-4 mr-2" />
            AI Insights
          </TabsTrigger>
          <TabsTrigger value="vulnerabilities">
            <Shield className="w-4 h-4 mr-2" />
            Vulnerabilities
          </TabsTrigger>
          <TabsTrigger value="trends">
            <TrendingUp className="w-4 h-4 mr-2" />
            Security Trends
          </TabsTrigger>
        </TabsList>

        {/* Code Analyzer Tab */}
        <TabsContent value="analyzer" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Code Input */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Code2 className="w-5 h-5 mr-2 text-blue-400" />
                  Code Analysis Input
                </CardTitle>
                <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Paste your code below for AI-powered security analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Textarea
                  placeholder="Paste your code here..."
                  value={analysisCode || sampleCode}
                  onChange={(e) => setAnalysisCode(e.target.value)}
                  className={`h-64 font-mono text-sm ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-gray-50'}`}
                />
                <div className="flex space-x-2">
                  <Button 
                    onClick={performAnalysis} 
                    disabled={isAnalyzing}
                    className="flex-1"
                  >
                    {isAnalyzing ? (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 mr-2" />
                        Analyze Code
                      </>
                    )}
                  </Button>
                  <Button variant="outline" size="sm">
                    <Upload className="w-4 h-4 mr-2" />
                    Upload File
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Analysis Results */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Target className="w-5 h-5 mr-2 text-green-400" />
                  Analysis Results
                </CardTitle>
                <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  AI-powered security and quality analysis results
                </CardDescription>
              </CardHeader>
              <CardContent>
                {isAnalyzing ? (
                  <div className="space-y-4">
                    <div className="text-center py-8">
                      <RefreshCw className="w-8 h-8 mx-auto animate-spin text-blue-400 mb-4" />
                      <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        AI models are analyzing your code...
                      </p>
                    </div>
                    {['Syntax Analysis', 'Security Scan', 'Quality Check', 'AI Insights'].map((stage, index) => (
                      <div key={index} className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{stage}</span>
                          <span className="text-blue-400">Processing...</span>
                        </div>
                        <Progress value={75} className="h-2" />
                      </div>
                    ))}
                  </div>
                ) : analysisResults ? (
                  <div className="space-y-4">
                    {/* Quick Stats */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className={`p-3 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                        <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {analysisResults.codeQuality.score}%
                        </div>
                        <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Quality Score
                        </div>
                      </div>
                      <div className={`p-3 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                        <div className={`text-lg font-bold text-red-400`}>
                          {analysisResults.vulnerability.critical + analysisResults.vulnerability.high}
                        </div>
                        <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Critical Issues
                        </div>
                      </div>
                    </div>

                    {/* Vulnerability Summary */}
                    <div>
                      <h4 className={`font-semibold mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        Vulnerability Summary
                      </h4>
                      <div className="space-y-2">
                        {[
                          { severity: 'Critical', count: analysisResults.vulnerability.critical, color: 'text-red-400' },
                          { severity: 'High', count: analysisResults.vulnerability.high, color: 'text-orange-400' },
                          { severity: 'Medium', count: analysisResults.vulnerability.medium, color: 'text-yellow-400' },
                          { severity: 'Low', count: analysisResults.vulnerability.low, color: 'text-blue-400' }
                        ].map((item, index) => (
                          <div key={index} className="flex justify-between">
                            <span className={`text-sm ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                              {item.severity}
                            </span>
                            <span className={`text-sm font-medium ${item.color}`}>
                              {item.count}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="grid grid-cols-2 gap-2">
                      <Button variant="outline" size="sm">
                        <Eye className="w-3 h-3 mr-1" />
                        View Details
                      </Button>
                      <Button variant="outline" size="sm">
                        <Download className="w-3 h-3 mr-1" />
                        Export Report
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Scan className="w-8 h-8 mx-auto text-gray-400 mb-4" />
                    <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                      Click "Analyze Code" to start AI-powered analysis
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* AI Insights Tab */}
        <TabsContent value="insights" className="mt-6">
          <div className="space-y-6">
            {ANALYSIS_RESULTS.aiInsights.map((insight, index) => (
              <Card key={index} className={`
                ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}
                transition-all duration-300 hover:scale-[1.02]
              `}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      {insight.type === 'security' && <Shield className="w-5 h-5 mr-2 text-red-400" />}
                      {insight.type === 'performance' && <Zap className="w-5 h-5 mr-2 text-orange-400" />}
                      {insight.type === 'code_quality' && <Code2 className="w-5 h-5 mr-2 text-blue-400" />}
                      {insight.title}
                    </CardTitle>
                    <div className="flex items-center space-x-2">
                      <Badge variant="outline" className={
                        insight.severity === 'high' ? 'text-red-400 border-red-400' :
                        insight.severity === 'medium' ? 'text-orange-400 border-orange-400' :
                        'text-blue-400 border-blue-400'
                      }>
                        {insight.severity}
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        {insight.confidence}% confidence
                      </Badge>
                    </div>
                  </div>
                  <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    {insight.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* File Location */}
                    <div className={`p-3 rounded-lg ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                      <div className="flex items-center space-x-2 text-sm">
                        <FileCode className="w-4 h-4 text-gray-400" />
                        <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>
                          {insight.file}:{insight.line}
                        </span>
                      </div>
                    </div>

                    {/* AI Suggestion */}
                    <div>
                      <h4 className={`flex items-center font-semibold text-sm mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        <Lightbulb className="w-4 h-4 mr-2 text-yellow-400" />
                        AI Recommendation
                      </h4>
                      <p className={`text-sm ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                        {insight.suggestion}
                      </p>
                    </div>

                    {/* AI Model */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2 text-xs">
                        <Brain className="w-3 h-3 text-purple-400" />
                        <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>
                          Analyzed by {insight.aiModel}
                        </span>
                      </div>
                      <div className="flex space-x-2">
                        <Button variant="outline" size="sm">
                          <Bug className="w-3 h-3 mr-1" />
                          Create Issue
                        </Button>
                        <Button variant="outline" size="sm">
                          <GitBranch className="w-3 h-3 mr-1" />
                          Auto-Fix
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Vulnerabilities Tab */}
        <TabsContent value="vulnerabilities" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Vulnerability Stats */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Shield className="w-5 h-5 mr-2 text-red-400" />
                  Vulnerability Overview
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { level: 'Critical', count: 3, color: 'text-red-400', bgColor: 'bg-red-400/10' },
                    { level: 'High', count: 12, color: 'text-orange-400', bgColor: 'bg-orange-400/10' },
                    { level: 'Medium', count: 27, color: 'text-yellow-400', bgColor: 'bg-yellow-400/10' },
                    { level: 'Low', count: 45, color: 'text-blue-400', bgColor: 'bg-blue-400/10' },
                    { level: 'Info', count: 18, color: 'text-gray-400', bgColor: 'bg-gray-400/10' }
                  ].map((vuln, index) => (
                    <div key={index} className={`p-3 rounded-lg ${vuln.bgColor}`}>
                      <div className="flex items-center justify-between">
                        <span className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                          {vuln.level}
                        </span>
                        <span className={`text-lg font-bold ${vuln.color}`}>
                          {vuln.count}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Vulnerability Types */}
            <Card className={`lg:col-span-2 ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Bug className="w-5 h-5 mr-2 text-orange-400" />
                  Vulnerability Distribution
                </CardTitle>
                <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Distribution of vulnerability types found in your code
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={[
                    { category: 'Injection', count: 15, severity: 'high' },
                    { category: 'XSS', count: 8, severity: 'medium' },
                    { category: 'Auth Issues', count: 12, severity: 'critical' },
                    { category: 'Crypto Errors', count: 6, severity: 'high' },
                    { category: 'Config Issues', count: 22, severity: 'medium' },
                    { category: 'Input Validation', count: 19, severity: 'low' }
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                    <XAxis dataKey="category" stroke={isDark ? "#9CA3AF" : "#6B7280"} />
                    <YAxis stroke={isDark ? "#9CA3AF" : "#6B7280"} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#18181b' : '#ffffff', 
                        border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}
                    />
                    <Bar dataKey="count" fill="#3B82F6" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Security Trends Tab */}
        <TabsContent value="trends" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <TrendingUp className="w-5 h-5 mr-2 text-green-400" />
                Security Health Trends
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Track your security posture improvements over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <AreaChart data={trendsData}>
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
                  <Area 
                    type="monotone" 
                    dataKey="vulnerabilities" 
                    stackId="1" 
                    stroke="#EF4444" 
                    fill="#EF4444" 
                    fillOpacity={0.3}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="fixes" 
                    stackId="2" 
                    stroke="#10B981" 
                    fill="#10B981" 
                    fillOpacity={0.3}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SmartCodeAnalyzer; 