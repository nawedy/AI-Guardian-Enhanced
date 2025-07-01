// src/components/security/SecurityManager.jsx
// Enhanced Security & Language Support Manager - v4.2.0
"use client"

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Code, 
  Brain, 
  AlertTriangle, 
  CheckCircle, 
  Activity,
  RefreshCw,
  Globe,
  TrendingUp,
  Bug,
  Lock,
  Wrench
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

const SUPPORTED_LANGUAGES = {
  python: { name: 'Python', icon: '🐍', version: '3.12+', coverage: 98, aiSupport: true },
  javascript: { name: 'JavaScript', icon: '🟨', version: 'ES2024', coverage: 95, aiSupport: true },
  typescript: { name: 'TypeScript', icon: '🔷', version: '5.3+', coverage: 96, aiSupport: true },
  java: { name: 'Java', icon: '☕', version: '21 LTS', coverage: 94, aiSupport: true },
  csharp: { name: 'C#', icon: '💜', version: '.NET 8', coverage: 93, aiSupport: true },
  go: { name: 'Go', icon: '🔵', version: '1.21+', coverage: 91, aiSupport: true },
  rust: { name: 'Rust', icon: '🦀', version: '1.75+', coverage: 89, aiSupport: true },
  php: { name: 'PHP', icon: '🐘', version: '8.3+', coverage: 92, aiSupport: true },
  ruby: { name: 'Ruby', icon: '💎', version: '3.3+', coverage: 90, aiSupport: true },
  kotlin: { name: 'Kotlin', icon: '🟣', version: '1.9+', coverage: 88, aiSupport: true }
};

const SecurityManager = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');

  const stats = {
    totalScans: 1847,
    vulnerabilitiesFound: 342,
    criticalIssues: 23,
    securityScore: 87
  };

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Enhanced Security & Language Support
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            AI-powered security with comprehensive language support
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-green-400 border-green-400">
            <CheckCircle className="w-3 h-3 mr-1" />
            {Object.keys(SUPPORTED_LANGUAGES).length} Languages Active
          </Badge>
          <Badge variant="outline" className="text-purple-400 border-purple-400">
            <Brain className="w-3 h-3 mr-1" />
            AI Enhanced
          </Badge>
          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Run Security Scan
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-5 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="languages">
            <Code className="w-4 h-4 mr-2" />
            Languages
          </TabsTrigger>
          <TabsTrigger value="detection">
            <Shield className="w-4 h-4 mr-2" />
            Detection
          </TabsTrigger>
          <TabsTrigger value="remediation">
            <Brain className="w-4 h-4 mr-2" />
            AI Remediation
          </TabsTrigger>
          <TabsTrigger value="policies">
            <Lock className="w-4 h-4 mr-2" />
            Policies
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6 mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Total Scans', value: stats.totalScans.toLocaleString(), icon: Activity, color: 'text-blue-400' },
              { title: 'Vulnerabilities Found', value: stats.vulnerabilitiesFound, icon: Bug, color: 'text-red-400' },
              { title: 'Critical Issues', value: stats.criticalIssues, icon: AlertTriangle, color: 'text-orange-400' },
              { title: 'Security Score', value: `${stats.securityScore}%`, icon: Shield, color: 'text-green-400' }
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
        </TabsContent>

        <TabsContent value="languages" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Globe className="w-5 h-5 mr-2" />
                Language Support Matrix
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                {Object.entries(SUPPORTED_LANGUAGES).map(([key, lang]) => (
                  <div key={key} className={`
                    p-3 rounded-lg border transition-all duration-200 hover:scale-105
                    ${isDark ? 'border-zinc-700 bg-zinc-800/50' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div className="flex items-center space-x-2 mb-2">
                      <span className="text-lg">{lang.icon}</span>
                      <span className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        {lang.name}
                      </span>
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Coverage</span>
                        <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{lang.coverage}%</span>
                      </div>
                      <Progress value={lang.coverage} className="h-1" />
                      <div className="flex items-center space-x-1 mt-1">
                        {lang.aiSupport && <Brain className="w-3 h-3 text-purple-400" />}
                        <Wrench className="w-3 h-3 text-green-400" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="detection" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle>Vulnerability Detection Engine</CardTitle>
            </CardHeader>
            <CardContent>
              <p className={isDark ? 'text-zinc-400' : 'text-gray-600'}>
                Advanced detection patterns and security analysis
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="remediation" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle>AI-Powered Remediation</CardTitle>
            </CardHeader>
            <CardContent>
              <p className={isDark ? 'text-zinc-400' : 'text-gray-600'}>
                Intelligent code fixes and security improvements
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="policies" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle>Security Policies</CardTitle>
            </CardHeader>
            <CardContent>
              <p className={isDark ? 'text-zinc-400' : 'text-gray-600'}>
                Compliance and security policy management
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SecurityManager;
