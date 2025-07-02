"use client"

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  UserShield, 
  FileCheck, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw,
  TrendingUp,
  Bug,
  Lock,
  Eye,
  Users,
  Database,
  Globe,
  Scale,
  Gavel,
  FileText,
  Clock,
  Settings,
  Zap,
  Brain,
  Key,
  CreditCard,
  Hospital,
  Building
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

// Comprehensive Security, Privacy & Compliance Data
const SECURITY_STATS = {
  vulnerabilities: { critical: 23, high: 67, medium: 142, low: 89, total: 321 },
  threats: { active: 12, mitigated: 89, investigating: 5 },
  scanEngines: 25,
  detectionRules: 2347,
  autoFixes: { applied: 1342, success: 94.2 },
  languages: 25
};

const PRIVACY_STATS = {
  dataTypes: { pii: 156, phi: 23, pci: 34, sensitive: 87 },
  dataFlows: { monitored: 89, encrypted: 78, anonymized: 45 },
  consent: { collected: 2347, active: 2156, expired: 191 },
  retention: { policies: 23, enforced: 21, pending: 2 },
  breachRisk: { low: 234, medium: 45, high: 12, critical: 3 }
};

const COMPLIANCE_STATS = {
  frameworks: {
    gdpr: { score: 94, violations: 5, status: 'compliant' },
    hipaa: { score: 89, violations: 12, status: 'needs_attention' },
    pciDss: { score: 96, violations: 2, status: 'compliant' },
    sox: { score: 87, violations: 8, status: 'needs_attention' },
    iso27001: { score: 91, violations: 6, status: 'compliant' },
    ccpa: { score: 93, violations: 4, status: 'compliant' },
    nist: { score: 88, violations: 9, status: 'needs_attention' },
    fedramp: { score: 85, violations: 11, status: 'non_compliant' }
  },
  audits: { scheduled: 12, completed: 8, overdue: 2, findings: 34 },
  policies: { total: 847, active: 823, outdated: 24, violations: 156 }
};

// Mock data for charts
const TRIFECTA_TRENDS = [
  { date: '2024-01-08', security: 85, privacy: 82, compliance: 87 },
  { date: '2024-01-09', security: 87, privacy: 84, compliance: 88 },
  { date: '2024-01-10', security: 86, privacy: 86, compliance: 89 },
  { date: '2024-01-11', security: 89, privacy: 87, compliance: 91 },
  { date: '2024-01-12', security: 91, privacy: 89, compliance: 92 },
  { date: '2024-01-13', security: 90, privacy: 91, compliance: 94 },
  { date: '2024-01-14', security: 92, privacy: 90, compliance: 93 }
];

const VULNERABILITY_DISTRIBUTION = [
  { name: 'Critical', value: SECURITY_STATS.vulnerabilities.critical, color: '#EF4444' },
  { name: 'High', value: SECURITY_STATS.vulnerabilities.high, color: '#F97316' },
  { name: 'Medium', value: SECURITY_STATS.vulnerabilities.medium, color: '#EAB308' },
  { name: 'Low', value: SECURITY_STATS.vulnerabilities.low, color: '#3B82F6' }
];

const PRIVACY_DATA_TYPES = [
  { name: 'PII', value: PRIVACY_STATS.dataTypes.pii, color: '#8B5CF6' },
  { name: 'PHI', value: PRIVACY_STATS.dataTypes.phi, color: '#EC4899' },
  { name: 'PCI', value: PRIVACY_STATS.dataTypes.pci, color: '#10B981' },
  { name: 'Sensitive', value: PRIVACY_STATS.dataTypes.sensitive, color: '#F59E0B' }
];

const ComprehensiveSecurityManager = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');

  const overallScore = Math.round((92 + 89 + 91) / 3); // Security, Privacy, Compliance average

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Security, Privacy & Compliance Management
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Comprehensive trifecta protection with AI-powered monitoring and automation
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-green-400 border-green-400">
            <CheckCircle className="w-3 h-3 mr-1" />
            Overall Score: {overallScore}%
          </Badge>
          <Badge variant="outline" className="text-blue-400 border-blue-400">
            <Brain className="w-3 h-3 mr-1" />
            AI Enhanced
          </Badge>
          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Full System Scan
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-6 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="security">
            <Shield className="w-4 h-4 mr-2" />
            Security
          </TabsTrigger>
          <TabsTrigger value="privacy">
            <UserShield className="w-4 h-4 mr-2" />
            Privacy
          </TabsTrigger>
          <TabsTrigger value="compliance">
            <FileCheck className="w-4 h-4 mr-2" />
            Compliance
          </TabsTrigger>
          <TabsTrigger value="analytics">
            <TrendingUp className="w-4 h-4 mr-2" />
            Analytics
          </TabsTrigger>
          <TabsTrigger value="policies">
            <Gavel className="w-4 h-4 mr-2" />
            Policies
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Trifecta Score Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              { 
                title: 'Security Score', 
                score: 92, 
                icon: Shield, 
                color: 'text-red-400',
                description: 'Vulnerability management & threat protection',
                metrics: [
                  { label: 'Active Threats', value: SECURITY_STATS.threats.active },
                  { label: 'Critical Vulns', value: SECURITY_STATS.vulnerabilities.critical },
                  { label: 'Auto-fixes', value: `${SECURITY_STATS.autoFixes.success}%` }
                ]
              },
              { 
                title: 'Privacy Score', 
                score: 89, 
                icon: UserShield, 
                color: 'text-purple-400',
                description: 'Data protection & user privacy controls',
                metrics: [
                  { label: 'Data Types', value: Object.values(PRIVACY_STATS.dataTypes).reduce((a, b) => a + b, 0) },
                  { label: 'Active Consent', value: PRIVACY_STATS.consent.active },
                  { label: 'Encrypted Flows', value: PRIVACY_STATS.dataFlows.encrypted }
                ]
              },
              { 
                title: 'Compliance Score', 
                score: 91, 
                icon: FileCheck, 
                color: 'text-green-400',
                description: 'Regulatory compliance & governance',
                metrics: [
                  { label: 'Frameworks', value: Object.keys(COMPLIANCE_STATS.frameworks).length },
                  { label: 'Active Policies', value: COMPLIANCE_STATS.policies.active },
                  { label: 'Pending Audits', value: COMPLIANCE_STATS.audits.scheduled }
                ]
              }
            ].map((pillar, index) => (
              <Card key={index} className={`
                transition-all duration-300 hover:scale-105
                ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}
              `}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      <pillar.icon className={`h-5 w-5 mr-2 ${pillar.color}`} />
                      {pillar.title}
                    </CardTitle>
                    <div className={`text-2xl font-bold ${pillar.color}`}>
                      {pillar.score}%
                    </div>
                  </div>
                  <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    {pillar.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <Progress value={pillar.score} className="h-2" />
                    <div className="grid grid-cols-3 gap-2 text-sm">
                      {pillar.metrics.map((metric, idx) => (
                        <div key={idx} className="text-center">
                          <div className={`font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {metric.value}
                          </div>
                          <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {metric.label}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Trifecta Trends Chart */}
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <TrendingUp className="w-5 h-5 mr-2 text-blue-400" />
                Security, Privacy & Compliance Trends (7 days)
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Comprehensive trifecta performance monitoring
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={TRIFECTA_TRENDS}>
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
                  <Area type="monotone" dataKey="security" stackId="1" stroke="#EF4444" fill="#EF4444" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="privacy" stackId="2" stroke="#8B5CF6" fill="#8B5CF6" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="compliance" stackId="3" stroke="#10B981" fill="#10B981" fillOpacity={0.3} />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Vulnerability Distribution */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Bug className="w-5 h-5 mr-2 text-red-400" />
                  Vulnerability Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={VULNERABILITY_DISTRIBUTION}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      fill="#8884d8"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {VULNERABILITY_DISTRIBUTION.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Security Engines */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Shield className="w-5 h-5 mr-2 text-blue-400" />
                  Active Security Engines
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { name: 'SAST Scanner', status: 'active', coverage: 98 },
                    { name: 'DAST Scanner', status: 'active', coverage: 94 },
                    { name: 'SCA Scanner', status: 'active', coverage: 96 },
                    { name: 'Container Scanner', status: 'active', coverage: 92 },
                    { name: 'Infrastructure Scanner', status: 'active', coverage: 89 },
                    { name: 'AI/ML Scanner', status: 'active', coverage: 87 }
                  ].map((engine, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                        <span className={`${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                          {engine.name}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Progress value={engine.coverage} className="w-16 h-2" />
                        <span className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {engine.coverage}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Privacy Tab */}
        <TabsContent value="privacy" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Data Types Distribution */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Database className="w-5 h-5 mr-2 text-purple-400" />
                  Sensitive Data Types
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={PRIVACY_DATA_TYPES}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      fill="#8884d8"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {PRIVACY_DATA_TYPES.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Privacy Controls */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <UserShield className="w-5 h-5 mr-2 text-green-400" />
                  Privacy Controls
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { name: 'Data Encryption', status: 'active', coverage: 98, icon: Lock },
                    { name: 'Consent Management', status: 'active', coverage: 94, icon: Users },
                    { name: 'Data Anonymization', status: 'active', coverage: 87, icon: Eye },
                    { name: 'Access Controls', status: 'active', coverage: 96, icon: Key },
                    { name: 'Data Retention', status: 'active', coverage: 89, icon: Clock },
                    { name: 'Breach Detection', status: 'active', coverage: 92, icon: AlertTriangle }
                  ].map((control, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <control.icon className="w-4 h-4 text-blue-400" />
                        <span className={`${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                          {control.name}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Progress value={control.coverage} className="w-16 h-2" />
                        <span className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {control.coverage}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="mt-6">
          <div className="space-y-6">
            {/* Compliance Frameworks */}
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Scale className="w-5 h-5 mr-2 text-blue-400" />
                  Regulatory Compliance Frameworks
                </CardTitle>
                <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Comprehensive compliance monitoring across major regulatory frameworks
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {Object.entries(COMPLIANCE_STATS.frameworks).map(([key, framework]) => (
                    <div key={key} className={`
                      p-4 rounded-lg border
                      ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                    `}>
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          {key === 'gdpr' && <Globe className="w-4 h-4 text-blue-400" />}
                          {key === 'hipaa' && <Hospital className="w-4 h-4 text-green-400" />}
                          {key === 'pciDss' && <CreditCard className="w-4 h-4 text-purple-400" />}
                          {key === 'sox' && <Building className="w-4 h-4 text-orange-400" />}
                          {key === 'iso27001' && <Shield className="w-4 h-4 text-cyan-400" />}
                          {key === 'ccpa' && <UserShield className="w-4 h-4 text-pink-400" />}
                          {key === 'nist' && <FileCheck className="w-4 h-4 text-indigo-400" />}
                          {key === 'fedramp' && <Gavel className="w-4 h-4 text-red-400" />}
                          <span className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {key.toUpperCase()}
                          </span>
                        </div>
                        <Badge variant="outline" className={
                          framework.status === 'compliant' ? 'text-green-400 border-green-400' :
                          framework.status === 'needs_attention' ? 'text-orange-400 border-orange-400' :
                          'text-red-400 border-red-400'
                        }>
                          {framework.score}%
                        </Badge>
                      </div>
                      <div className="space-y-2">
                        <Progress value={framework.score} className="h-2" />
                        <div className="flex justify-between text-sm">
                          <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            Violations: {framework.violations}
                          </span>
                          <span className={
                            framework.status === 'compliant' ? 'text-green-400' :
                            framework.status === 'needs_attention' ? 'text-orange-400' :
                            'text-red-400'
                          }>
                            {framework.status.replace('_', ' ')}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <TrendingUp className="w-5 h-5 mr-2 text-blue-400" />
                Comprehensive Analytics Dashboard
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Advanced analytics for Security, Privacy & Compliance performance tracking
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <Brain className="w-16 h-16 mx-auto text-gray-400 mb-4" />
                <h3 className={`text-lg font-semibold mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  Advanced Analytics Coming Soon
                </h3>
                <p className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Comprehensive dashboards for cross-pillar analytics and insights
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Policies Tab */}
        <TabsContent value="policies" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Gavel className="w-5 h-5 mr-2 text-green-400" />
                Policy Management Center
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Centralized policy management for Security, Privacy & Compliance
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <FileCheck className="w-16 h-16 mx-auto text-gray-400 mb-4" />
                <h3 className={`text-lg font-semibold mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  Policy Management Center Coming Soon
                </h3>
                <p className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Comprehensive policy authoring, versioning, and enforcement tools
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ComprehensiveSecurityManager; 