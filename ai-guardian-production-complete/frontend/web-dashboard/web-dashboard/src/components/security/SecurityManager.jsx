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
  // Tier 1: Primary Enterprise Languages (98-95% coverage)
  python: { name: 'Python', icon: '🐍', version: '3.12+', coverage: 98, aiSupport: true, tier: 1, scanEngine: 'bandit-pro', vulnerabilities: 147 },
  javascript: { name: 'JavaScript', icon: '🟨', version: 'ES2024', coverage: 97, aiSupport: true, tier: 1, scanEngine: 'eslint-security-pro', vulnerabilities: 134 },
  typescript: { name: 'TypeScript', icon: '🔷', version: '5.3+', coverage: 96, aiSupport: true, tier: 1, scanEngine: 'ts-security-pro', vulnerabilities: 142 },
  java: { name: 'Java', icon: '☕', version: '21 LTS', coverage: 95, aiSupport: true, tier: 1, scanEngine: 'spotbugs-security', vulnerabilities: 156 },
  csharp: { name: 'C#', icon: '💜', version: '.NET 8', coverage: 95, aiSupport: true, tier: 1, scanEngine: 'security-code-scan', vulnerabilities: 128 },

  // Tier 2: Modern System Languages (94-90% coverage)
  go: { name: 'Go', icon: '🔵', version: '1.21+', coverage: 94, aiSupport: true, tier: 2, scanEngine: 'gosec-pro', vulnerabilities: 98 },
  rust: { name: 'Rust', icon: '🦀', version: '1.75+', coverage: 93, aiSupport: true, tier: 2, scanEngine: 'cargo-audit-pro', vulnerabilities: 87 },
  swift: { name: 'Swift', icon: '🍎', version: '5.9+', coverage: 92, aiSupport: true, tier: 2, scanEngine: 'swiftlint-security', vulnerabilities: 76 },
  kotlin: { name: 'Kotlin', icon: '🟣', version: '1.9+', coverage: 91, aiSupport: true, tier: 2, scanEngine: 'detekt-security', vulnerabilities: 92 },
  dart: { name: 'Dart', icon: '🎯', version: '3.2+', coverage: 90, aiSupport: true, tier: 2, scanEngine: 'dart-analyze-security', vulnerabilities: 68 },

  // Tier 3: Web & Scripting Languages (89-85% coverage)
  php: { name: 'PHP', icon: '🐘', version: '8.3+', coverage: 89, aiSupport: true, tier: 3, scanEngine: 'psalm-security', vulnerabilities: 119 },
  ruby: { name: 'Ruby', icon: '💎', version: '3.3+', coverage: 88, aiSupport: true, tier: 3, scanEngine: 'brakeman-pro', vulnerabilities: 104 },
  scala: { name: 'Scala', icon: '⚡', version: '3.3+', coverage: 87, aiSupport: true, tier: 3, scanEngine: 'scalafix-security', vulnerabilities: 85 },
  perl: { name: 'Perl', icon: '🐪', version: '5.38+', coverage: 86, aiSupport: true, tier: 3, scanEngine: 'perl-critic-security', vulnerabilities: 73 },
  lua: { name: 'Lua', icon: '🌙', version: '5.4+', coverage: 85, aiSupport: true, tier: 3, scanEngine: 'luacheck-security', vulnerabilities: 45 },

  // Tier 4: System & Low-Level Languages (84-80% coverage)
  cpp: { name: 'C++', icon: '⚙️', version: 'C++23', coverage: 84, aiSupport: true, tier: 4, scanEngine: 'clang-static-analyzer', vulnerabilities: 167 },
  c: { name: 'C', icon: '🔧', version: 'C23', coverage: 83, aiSupport: true, tier: 4, scanEngine: 'clang-static-analyzer', vulnerabilities: 145 },
  objectivec: { name: 'Objective-C', icon: '🍏', version: '2.0+', coverage: 82, aiSupport: true, tier: 4, scanEngine: 'clang-static-analyzer', vulnerabilities: 89 },
  elixir: { name: 'Elixir', icon: '💧', version: '1.15+', coverage: 81, aiSupport: true, tier: 4, scanEngine: 'sobelow', vulnerabilities: 52 },
  haskell: { name: 'Haskell', icon: 'λ', version: 'GHC 9.6+', coverage: 80, aiSupport: true, tier: 4, scanEngine: 'hlint-security', vulnerabilities: 38 },

  // Tier 5: Specialized & Domain-Specific Languages (79-75% coverage)
  r: { name: 'R', icon: '📊', version: '4.3+', coverage: 79, aiSupport: true, tier: 5, scanEngine: 'lintr-security', vulnerabilities: 42 },
  matlab: { name: 'MATLAB', icon: '🧮', version: 'R2023b+', coverage: 78, aiSupport: true, tier: 5, scanEngine: 'mlint-security', vulnerabilities: 35 },
  julia: { name: 'Julia', icon: '🔬', version: '1.9+', coverage: 77, aiSupport: true, tier: 5, scanEngine: 'julia-security-lint', vulnerabilities: 31 },
  fsharp: { name: 'F#', icon: '🔷', version: '.NET 8', coverage: 76, aiSupport: true, tier: 5, scanEngine: 'fsharp-lint-security', vulnerabilities: 29 },
  clojure: { name: 'Clojure', icon: '🔗', version: '1.11+', coverage: 75, aiSupport: true, tier: 5, scanEngine: 'clj-kondo-security', vulnerabilities: 27 }
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
           <div className="space-y-6">
             {/* Language Support Overview */}
             <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
               <CardHeader>
                 <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                   <Globe className="w-5 h-5 mr-2" />
                   Language Support Matrix ({Object.keys(SUPPORTED_LANGUAGES).length} Languages)
                 </CardTitle>
                 <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                   Comprehensive security coverage across enterprise and specialized programming languages
                 </CardDescription>
               </CardHeader>
               <CardContent>
                 <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                   {[1, 2, 3, 4, 5].map(tier => {
                     const tierLangs = Object.entries(SUPPORTED_LANGUAGES).filter(([, lang]) => lang.tier === tier);
                     const avgCoverage = Math.round(tierLangs.reduce((sum, [, lang]) => sum + lang.coverage, 0) / tierLangs.length);
                     const tierNames = {
                       1: 'Enterprise Core',
                       2: 'Modern Systems', 
                       3: 'Web & Scripting',
                       4: 'System & Low-Level',
                       5: 'Specialized & Domain'
                     };
                     const tierColors = {
                       1: 'text-green-400 border-green-400',
                       2: 'text-blue-400 border-blue-400',
                       3: 'text-purple-400 border-purple-400',
                       4: 'text-orange-400 border-orange-400',
                       5: 'text-cyan-400 border-cyan-400'
                     };
                     
                     return (
                       <div key={tier} className={`p-4 rounded-lg border ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}`}>
                         <div className="flex items-center justify-between mb-2">
                           <Badge variant="outline" className={tierColors[tier]}>
                             Tier {tier}
                           </Badge>
                           <span className={`text-sm font-medium ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                             {avgCoverage}% avg
                           </span>
                         </div>
                         <h4 className={`font-semibold text-sm mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                           {tierNames[tier]}
                         </h4>
                         <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                           {tierLangs.length} languages supported
                         </p>
                       </div>
                     );
                   })}
                 </div>

                 {/* Language Grid by Tiers */}
                 {[1, 2, 3, 4, 5].map(tier => {
                   const tierLangs = Object.entries(SUPPORTED_LANGUAGES).filter(([, lang]) => lang.tier === tier);
                   const tierNames = {
                     1: 'Tier 1: Enterprise Core Languages',
                     2: 'Tier 2: Modern System Languages', 
                     3: 'Tier 3: Web & Scripting Languages',
                     4: 'Tier 4: System & Low-Level Languages',
                     5: 'Tier 5: Specialized & Domain Languages'
                   };
                   
                   return (
                     <div key={tier} className="mb-6">
                       <h4 className={`font-semibold mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                         {tierNames[tier]}
                       </h4>
                       <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                         {tierLangs.map(([key, lang]) => (
                           <div key={key} className={`
                             p-3 rounded-lg border transition-all duration-200 hover:scale-105
                             ${isDark ? 'border-zinc-700 bg-zinc-800/50' : 'border-gray-200 bg-gray-50'}
                           `}>
                             <div className="flex items-center space-x-2 mb-2">
                               <span className="text-lg">{lang.icon}</span>
                               <div className="flex-1 min-w-0">
                                 <span className={`font-semibold text-xs block truncate ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                                   {lang.name}
                                 </span>
                                 <span className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                                   {lang.version}
                                 </span>
                               </div>
                             </div>
                             <div className="space-y-1">
                               <div className="flex justify-between text-xs">
                                 <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Coverage</span>
                                 <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{lang.coverage}%</span>
                               </div>
                               <Progress value={lang.coverage} className="h-1" />
                               <div className="flex items-center justify-between">
                                 <div className="flex items-center space-x-1">
                                   {lang.aiSupport && <Brain className="w-3 h-3 text-purple-400" />}
                                   <Wrench className="w-3 h-3 text-green-400" />
                                 </div>
                                 <span className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                                   {lang.vulnerabilities} rules
                                 </span>
                               </div>
                             </div>
                           </div>
                         ))}
                       </div>
                     </div>
                   );
                 })}
               </CardContent>
             </Card>
           </div>
         </TabsContent>

                 <TabsContent value="detection" className="mt-6">
           <div className="space-y-6">
             {/* Vulnerability Detection Stats */}
             <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
               {[
                 { name: 'Active Scan Engines', value: '25', icon: Shield, trend: '+3', color: 'text-blue-400' },
                 { name: 'Detection Rules', value: '2,347', icon: Code, trend: '+127', color: 'text-green-400' },
                 { name: 'Threat Patterns', value: '1,892', icon: AlertTriangle, trend: '+45', color: 'text-orange-400' },
                 { name: 'AI Models Active', value: '12', icon: Brain, trend: '+2', color: 'text-purple-400' }
               ].map((stat, index) => (
                 <Card key={index} className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                   <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                     <CardTitle className={`text-sm font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                       {stat.name}
                     </CardTitle>
                     <stat.icon className={`h-4 w-4 ${stat.color}`} />
                   </CardHeader>
                   <CardContent>
                     <div className={`text-2xl font-bold ${isDark ? 'text-zinc-50' : 'text-gray-900'}`}>
                       {stat.value}
                     </div>
                     <p className={`text-xs text-green-400`}>
                       {stat.trend} this month
                     </p>
                   </CardContent>
                 </Card>
               ))}
             </div>

             {/* Threat Intelligence & Detection Engines */}
             <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
               {/* Threat Intelligence Feeds */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <Shield className="w-5 h-5 mr-2 text-blue-400" />
                     Threat Intelligence Feeds
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Real-time threat intelligence from global security networks
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {[
                       { name: 'MITRE ATT&CK', status: 'active', lastUpdate: '2 min ago', threats: 342 },
                       { name: 'CVE Database', status: 'active', lastUpdate: '15 min ago', threats: 1847 },
                       { name: 'Zero-Day Tracker', status: 'active', lastUpdate: '1 hour ago', threats: 23 },
                       { name: 'Malware Signatures', status: 'active', lastUpdate: '5 min ago', threats: 892 },
                       { name: 'IoC Feeds', status: 'active', lastUpdate: '12 min ago', threats: 567 },
                       { name: 'Dark Web Intel', status: 'active', lastUpdate: '30 min ago', threats: 45 }
                     ].map((feed, index) => (
                       <div key={index} className={`
                         p-3 rounded-lg border
                         ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                       `}>
                         <div className="flex items-center justify-between">
                           <div className="flex items-center space-x-3">
                             <div className="w-2 h-2 rounded-full bg-green-400"></div>
                             <div>
                               <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                                 {feed.name}
                               </h4>
                               <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                 Updated {feed.lastUpdate}
                               </p>
                             </div>
                           </div>
                           <Badge variant="outline" className="text-xs">
                             {feed.threats.toLocaleString()} threats
                           </Badge>
                         </div>
                       </div>
                     ))}
                   </div>
                 </CardContent>
               </Card>

               {/* Detection Engines by Category */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <Code className="w-5 h-5 mr-2 text-green-400" />
                     Detection Engine Performance
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Real-time performance metrics for all active scan engines
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {[
                       { category: 'SAST Engines', engines: 15, active: 15, performance: 98, color: 'text-green-400' },
                       { category: 'DAST Engines', engines: 8, active: 7, performance: 94, color: 'text-blue-400' },
                       { category: 'SCA Engines', engines: 12, active: 12, performance: 96, color: 'text-purple-400' },
                       { category: 'Container Scanners', engines: 6, active: 6, performance: 92, color: 'text-orange-400' },
                       { category: 'Infrastructure', engines: 9, active: 8, performance: 89, color: 'text-cyan-400' },
                       { category: 'AI/ML Models', engines: 4, active: 4, performance: 97, color: 'text-pink-400' }
                     ].map((engine, index) => (
                       <div key={index} className={`
                         p-3 rounded-lg border
                         ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                       `}>
                         <div className="flex items-center justify-between mb-2">
                           <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                             {engine.category}
                           </h4>
                           <div className="flex items-center space-x-2">
                             <Badge variant="outline" className={engine.color}>
                               {engine.active}/{engine.engines} active
                             </Badge>
                             <span className={`text-xs font-medium ${engine.color}`}>
                               {engine.performance}%
                             </span>
                           </div>
                         </div>
                         <Progress value={engine.performance} className="h-2" />
                       </div>
                     ))}
                   </div>
                 </CardContent>
               </Card>
             </div>

             {/* Advanced Security Detection Categories */}
             <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
               <CardHeader>
                 <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                   <AlertTriangle className="w-5 h-5 mr-2 text-red-400" />
                   Advanced Vulnerability Detection Categories
                 </CardTitle>
                 <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                   Comprehensive vulnerability detection across all attack vectors
                 </CardDescription>
               </CardHeader>
               <CardContent>
                 <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                   {[
                     { name: 'Injection Attacks', detected: 89, severity: 'critical', rules: 247, trend: '-12%', icon: '💉' },
                     { name: 'XSS Vulnerabilities', detected: 67, severity: 'high', rules: 189, trend: '-8%', icon: '🔗' },
                     { name: 'Authentication Flaws', detected: 34, severity: 'high', rules: 156, trend: '+5%', icon: '🔐' },
                     { name: 'Access Control', detected: 45, severity: 'medium', rules: 134, trend: '-15%', icon: '🛡️' },
                     { name: 'Cryptographic Issues', detected: 23, severity: 'medium', rules: 98, trend: '+3%', icon: '🔑' },
                     { name: 'Security Misconfig', detected: 78, severity: 'medium', rules: 203, trend: '-20%', icon: '⚙️' },
                     { name: 'Vulnerable Components', detected: 156, severity: 'high', rules: 312, trend: '+7%', icon: '📦' },
                     { name: 'Data Exposure', detected: 29, severity: 'critical', rules: 87, trend: '-25%', icon: '📊' },
                     { name: 'Business Logic', detected: 18, severity: 'medium', rules: 64, trend: '+2%', icon: '🧠' },
                     { name: 'API Security', detected: 42, severity: 'high', rules: 145, trend: '-10%', icon: '🔌' },
                     { name: 'Mobile Security', detected: 35, severity: 'medium', rules: 112, trend: '+8%', icon: '📱' },
                     { name: 'Cloud Security', detected: 67, severity: 'high', rules: 189, trend: '-5%', icon: '☁️' }
                   ].map((category, index) => (
                     <div key={index} className={`
                       p-4 rounded-lg border transition-all duration-200 hover:scale-105
                       ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                     `}>
                       <div className="flex items-center justify-between mb-3">
                         <div className="flex items-center space-x-2">
                           <span className="text-lg">{category.icon}</span>
                           <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                             {category.name}
                           </h4>
                         </div>
                         <Badge variant="outline" className={
                           category.severity === 'critical' ? 'text-red-400 border-red-400' :
                           category.severity === 'high' ? 'text-orange-400 border-orange-400' :
                           'text-blue-400 border-blue-400'
                         }>
                           {category.severity}
                         </Badge>
                       </div>
                       
                       <div className="space-y-2">
                         <div className="flex justify-between items-center">
                           <span className={`text-2xl font-bold ${isDark ? 'text-zinc-50' : 'text-gray-900'}`}>
                             {category.detected}
                           </span>
                           <span className={`text-sm ${category.trend.startsWith('+') ? 'text-red-400' : 'text-green-400'}`}>
                             {category.trend}
                           </span>
                         </div>
                         <div className="flex justify-between text-xs">
                           <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>
                             {category.rules} detection rules
                           </span>
                           <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>
                             Last 30 days
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

                 <TabsContent value="remediation" className="mt-6">
           <div className="space-y-6">
             {/* AI Remediation Stats */}
             <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
               {[
                 { name: 'AI Models Active', value: '12', icon: Brain, trend: '+2', color: 'text-purple-400' },
                 { name: 'Auto-Fixes Applied', value: '1,342', icon: Wrench, trend: '+89', color: 'text-green-400' },
                 { name: 'Fix Success Rate', value: '94.2%', icon: CheckCircle, trend: '+2.1%', color: 'text-blue-400' },
                 { name: 'Time Saved', value: '847h', icon: TrendingUp, trend: '+156h', color: 'text-orange-400' }
               ].map((stat, index) => (
                 <Card key={index} className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                   <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                     <CardTitle className={`text-sm font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                       {stat.name}
                     </CardTitle>
                     <stat.icon className={`h-4 w-4 ${stat.color}`} />
                   </CardHeader>
                   <CardContent>
                     <div className={`text-2xl font-bold ${isDark ? 'text-zinc-50' : 'text-gray-900'}`}>
                       {stat.value}
                     </div>
                     <p className={`text-xs text-green-400`}>
                       {stat.trend} this month
                     </p>
                   </CardContent>
                 </Card>
               ))}
             </div>

             {/* AI Models & Remediation Engines */}
             <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
               {/* Active AI Models */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <Brain className="w-5 h-5 mr-2 text-purple-400" />
                     Active AI Remediation Models
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Advanced machine learning models for automated code fixes
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {[
                       { name: 'CodeT5-Security', type: 'Transformer', performance: 96, speciality: 'Code Generation', fixes: 342 },
                       { name: 'VulnGPT-Pro', type: 'GPT-4 Based', performance: 94, speciality: 'Vulnerability Analysis', fixes: 287 },
                       { name: 'SecureLLaMA', type: 'LLaMA Fine-tuned', performance: 92, speciality: 'Pattern Recognition', fixes: 198 },
                       { name: 'DeepScan-AI', type: 'Custom CNN', performance: 89, speciality: 'Static Analysis', fixes: 234 },
                       { name: 'AutoFix-BERT', type: 'BERT Variant', performance: 91, speciality: 'Context Understanding', fixes: 167 },
                       { name: 'SecureCodex', type: 'Multi-Modal', performance: 88, speciality: 'Cross-Language', fixes: 145 }
                     ].map((model, index) => (
                       <div key={index} className={`
                         p-3 rounded-lg border
                         ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                       `}>
                         <div className="flex items-center justify-between mb-2">
                           <div>
                             <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                               {model.name}
                             </h4>
                             <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                               {model.type} • {model.speciality}
                             </p>
                           </div>
                           <div className="text-right">
                             <div className={`text-sm font-medium ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                               {model.performance}%
                             </div>
                             <div className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                               {model.fixes} fixes
                             </div>
                           </div>
                         </div>
                         <Progress value={model.performance} className="h-2" />
                       </div>
                     ))}
                   </div>
                 </CardContent>
               </Card>

               {/* Remediation Analytics */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <Activity className="w-5 h-5 mr-2 text-green-400" />
                     Remediation Analytics
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Performance insights and effectiveness metrics
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-6">
                     {/* Remediation by Severity */}
                     <div>
                       <h4 className={`font-semibold text-sm mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                         Auto-Remediation by Severity
                       </h4>
                       <div className="space-y-3">
                         {[
                           { severity: 'Critical', total: 45, fixed: 42, rate: 93, color: 'text-red-400' },
                           { severity: 'High', total: 134, fixed: 127, rate: 95, color: 'text-orange-400' },
                           { severity: 'Medium', total: 298, fixed: 281, rate: 94, color: 'text-yellow-400' },
                           { severity: 'Low', total: 567, fixed: 534, rate: 94, color: 'text-blue-400' }
                         ].map((item, index) => (
                           <div key={index} className="flex items-center justify-between">
                             <div className="flex items-center space-x-2">
                               <Badge variant="outline" className={item.color}>
                                 {item.severity}
                               </Badge>
                               <span className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                 {item.fixed}/{item.total} fixed
                               </span>
                             </div>
                             <div className="flex items-center space-x-2">
                               <Progress value={item.rate} className="w-16 h-2" />
                               <span className={`text-sm font-medium ${item.color}`}>
                                 {item.rate}%
                               </span>
                             </div>
                           </div>
                         ))}
                       </div>
                     </div>

                     {/* Language-Specific Performance */}
                     <div>
                       <h4 className={`font-semibold text-sm mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                         Top Performing Languages
                       </h4>
                       <div className="space-y-2">
                         {[
                           { lang: 'Python', fixes: 287, rate: 97 },
                           { lang: 'JavaScript', fixes: 234, rate: 95 },
                           { lang: 'Java', fixes: 198, rate: 94 },
                           { lang: 'TypeScript', fixes: 176, rate: 96 },
                           { lang: 'Go', fixes: 143, rate: 92 }
                         ].map((lang, index) => (
                           <div key={index} className="flex items-center justify-between text-sm">
                             <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>
                               {lang.lang}
                             </span>
                             <div className="flex items-center space-x-2">
                               <span className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                                 {lang.fixes} fixes
                               </span>
                               <span className={`text-xs font-medium text-green-400`}>
                                 {lang.rate}%
                               </span>
                             </div>
                           </div>
                         ))}
                       </div>
                     </div>
                   </div>
                 </CardContent>
               </Card>
             </div>

             {/* Recent AI Fixes & Automated Remediation Queue */}
             <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
               {/* Recent AI Fixes */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <CheckCircle className="w-5 h-5 mr-2 text-green-400" />
                     Recent AI Fixes Applied
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Latest automated security fixes and improvements
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {[
                       { 
                         file: 'auth/login.py', 
                         issue: 'SQL Injection', 
                         fix: 'Parameterized queries', 
                         time: '2 min ago',
                         model: 'CodeT5-Security',
                         severity: 'critical'
                       },
                       { 
                         file: 'api/user.js', 
                         issue: 'XSS Vulnerability', 
                         fix: 'Input sanitization', 
                         time: '8 min ago',
                         model: 'VulnGPT-Pro',
                         severity: 'high'
                       },
                       { 
                         file: 'utils/crypto.go', 
                         issue: 'Weak Encryption', 
                         fix: 'AES-256 implementation', 
                         time: '15 min ago',
                         model: 'SecureLLaMA',
                         severity: 'medium'
                       },
                       { 
                         file: 'config/db.php', 
                         issue: 'Hardcoded Secrets', 
                         fix: 'Environment variables', 
                         time: '23 min ago',
                         model: 'DeepScan-AI',
                         severity: 'high'
                       },
                       { 
                         file: 'validation/input.ts', 
                         issue: 'Type Confusion', 
                         fix: 'Strict type checking', 
                         time: '31 min ago',
                         model: 'AutoFix-BERT',
                         severity: 'medium'
                       }
                     ].map((fix, index) => (
                       <div key={index} className={`
                         p-3 rounded-lg border
                         ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                       `}>
                         <div className="flex items-start justify-between mb-2">
                           <div className="flex-1">
                             <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                               {fix.file}
                             </h4>
                             <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                               {fix.issue} → {fix.fix}
                             </p>
                           </div>
                           <Badge variant="outline" className={
                             fix.severity === 'critical' ? 'text-red-400 border-red-400' :
                             fix.severity === 'high' ? 'text-orange-400 border-orange-400' :
                             'text-blue-400 border-blue-400'
                           }>
                             {fix.severity}
                           </Badge>
                         </div>
                         <div className="flex items-center justify-between text-xs">
                           <Badge variant="secondary" className="text-xs">
                             {fix.model}
                           </Badge>
                           <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                             {fix.time}
                           </span>
                         </div>
                       </div>
                     ))}
                   </div>
                 </CardContent>
               </Card>

               {/* Remediation Queue */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <RefreshCw className="w-5 h-5 mr-2 text-blue-400" />
                     Automated Remediation Queue
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Pending fixes and remediation pipeline status
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {/* Queue Stats */}
                     <div className="grid grid-cols-3 gap-4 mb-4">
                       {[
                         { label: 'In Queue', value: '47', color: 'text-blue-400' },
                         { label: 'Processing', value: '8', color: 'text-orange-400' },
                         { label: 'Pending Review', value: '12', color: 'text-purple-400' }
                       ].map((stat, index) => (
                         <div key={index} className={`text-center p-2 rounded ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                           <div className={`text-lg font-bold ${stat.color}`}>
                             {stat.value}
                           </div>
                           <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                             {stat.label}
                           </div>
                         </div>
                       ))}
                     </div>

                     {/* Processing Items */}
                     <div className="space-y-3">
                       {[
                         { file: 'database/queries.rb', issue: 'NoSQL Injection', priority: 'high', progress: 78 },
                         { file: 'middleware/auth.dart', issue: 'JWT Vulnerability', priority: 'medium', progress: 45 },
                         { file: 'services/payment.scala', issue: 'Race Condition', priority: 'high', progress: 92 },
                         { file: 'controllers/api.cpp', issue: 'Buffer Overflow', priority: 'critical', progress: 23 },
                         { file: 'validators/form.lua', issue: 'Input Validation', priority: 'medium', progress: 67 }
                       ].map((item, index) => (
                         <div key={index} className={`
                           p-3 rounded-lg border
                           ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                         `}>
                           <div className="flex items-center justify-between mb-2">
                             <div className="flex-1">
                               <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                                 {item.file}
                               </h4>
                               <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                 {item.issue}
                               </p>
                             </div>
                             <Badge variant="outline" className={
                               item.priority === 'critical' ? 'text-red-400 border-red-400' :
                               item.priority === 'high' ? 'text-orange-400 border-orange-400' :
                               'text-blue-400 border-blue-400'
                             }>
                               {item.priority}
                             </Badge>
                           </div>
                           <div className="flex items-center space-x-2">
                             <Progress value={item.progress} className="flex-1 h-2" />
                             <span className={`text-xs font-medium ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                               {item.progress}%
                             </span>
                           </div>
                         </div>
                       ))}
                     </div>
                   </div>
                 </CardContent>
               </Card>
             </div>
           </div>
         </TabsContent>

                 <TabsContent value="policies" className="mt-6">
           <div className="space-y-6">
             {/* Compliance Overview */}
             <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
               {[
                 { name: 'Compliance Score', value: '94.2%', icon: Shield, trend: '+2.1%', color: 'text-green-400' },
                 { name: 'Active Policies', value: '847', icon: Lock, trend: '+23', color: 'text-blue-400' },
                 { name: 'Policy Violations', value: '12', icon: AlertTriangle, trend: '-8', color: 'text-orange-400' },
                 { name: 'Frameworks', value: '8', icon: Globe, trend: '+1', color: 'text-purple-400' }
               ].map((stat, index) => (
                 <Card key={index} className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                   <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                     <CardTitle className={`text-sm font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                       {stat.name}
                     </CardTitle>
                     <stat.icon className={`h-4 w-4 ${stat.color}`} />
                   </CardHeader>
                   <CardContent>
                     <div className={`text-2xl font-bold ${isDark ? 'text-zinc-50' : 'text-gray-900'}`}>
                       {stat.value}
                     </div>
                     <p className={`text-xs text-green-400`}>
                       {stat.trend} this month
                     </p>
                   </CardContent>
                 </Card>
               ))}
             </div>

             {/* Compliance Frameworks */}
             <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
               {/* Security Frameworks Compliance */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <Shield className="w-5 h-5 mr-2 text-green-400" />
                     Security Frameworks Compliance
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Compliance status across major security frameworks
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {[
                       { name: 'OWASP Top 10', compliance: 98, controls: 147, violations: 3, status: 'excellent' },
                       { name: 'PCI DSS', compliance: 94, controls: 234, violations: 8, status: 'good' },
                       { name: 'SOC 2', compliance: 96, controls: 189, violations: 5, status: 'excellent' },
                       { name: 'ISO 27001', compliance: 91, controls: 312, violations: 12, status: 'good' },
                       { name: 'NIST Framework', compliance: 89, controls: 278, violations: 15, status: 'acceptable' },
                       { name: 'GDPR', compliance: 97, controls: 156, violations: 2, status: 'excellent' },
                       { name: 'HIPAA', compliance: 92, controls: 198, violations: 9, status: 'good' },
                       { name: 'FedRAMP', compliance: 87, controls: 345, violations: 18, status: 'acceptable' }
                     ].map((framework, index) => (
                       <div key={index} className={`
                         p-4 rounded-lg border
                         ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                       `}>
                         <div className="flex items-center justify-between mb-3">
                           <div>
                             <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                               {framework.name}
                             </h4>
                             <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                               {framework.controls} controls • {framework.violations} violations
                             </p>
                           </div>
                           <div className="text-right">
                             <Badge variant="outline" className={
                               framework.status === 'excellent' ? 'text-green-400 border-green-400' :
                               framework.status === 'good' ? 'text-blue-400 border-blue-400' :
                               'text-orange-400 border-orange-400'
                             }>
                               {framework.status}
                             </Badge>
                             <div className={`text-lg font-bold mt-1 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                               {framework.compliance}%
                             </div>
                           </div>
                         </div>
                         <Progress value={framework.compliance} className="h-2" />
                       </div>
                     ))}
                   </div>
                 </CardContent>
               </Card>

               {/* Policy Categories */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <Lock className="w-5 h-5 mr-2 text-blue-400" />
                     Active Security Policies
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Policy enforcement and compliance monitoring
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {[
                       { category: 'Authentication & Access', policies: 89, enforced: 87, violations: 2, icon: '🔐' },
                       { category: 'Data Protection', policies: 156, enforced: 152, violations: 4, icon: '🛡️' },
                       { category: 'Encryption Standards', policies: 67, enforced: 65, violations: 2, icon: '🔑' },
                       { category: 'Network Security', policies: 134, enforced: 129, violations: 5, icon: '🌐' },
                       { category: 'Code Security', policies: 298, enforced: 291, violations: 7, icon: '💻' },
                       { category: 'Infrastructure', policies: 78, enforced: 75, violations: 3, icon: '🏗️' },
                       { category: 'Third-Party Risk', policies: 45, enforced: 42, violations: 3, icon: '🤝' },
                       { category: 'Incident Response', policies: 34, enforced: 34, violations: 0, icon: '🚨' }
                     ].map((category, index) => (
                       <div key={index} className={`
                         p-3 rounded-lg border
                         ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                       `}>
                         <div className="flex items-center justify-between mb-2">
                           <div className="flex items-center space-x-2">
                             <span className="text-lg">{category.icon}</span>
                             <div>
                               <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                                 {category.category}
                               </h4>
                               <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                 {category.enforced}/{category.policies} enforced
                               </p>
                             </div>
                           </div>
                           <div className="text-right">
                             <div className={`text-sm font-medium ${
                               category.violations === 0 ? 'text-green-400' :
                               category.violations <= 3 ? 'text-yellow-400' :
                               'text-red-400'
                             }`}>
                               {category.violations} violations
                             </div>
                             <div className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                               {Math.round((category.enforced / category.policies) * 100)}% compliant
                             </div>
                           </div>
                         </div>
                         <Progress value={(category.enforced / category.policies) * 100} className="h-1" />
                       </div>
                     ))}
                   </div>
                 </CardContent>
               </Card>
             </div>

             {/* Policy Violations & Risk Assessment */}
             <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
               {/* Recent Policy Violations */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <AlertTriangle className="w-5 h-5 mr-2 text-orange-400" />
                     Recent Policy Violations
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Latest compliance violations and remediation status
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-4">
                     {[
                       { 
                         file: 'api/payment.js', 
                         violation: 'PCI DSS - Unencrypted card data', 
                         severity: 'critical', 
                         framework: 'PCI DSS',
                         time: '23 min ago',
                         status: 'remediating'
                       },
                       { 
                         file: 'auth/session.py', 
                         violation: 'OWASP - Weak session management', 
                         severity: 'high', 
                         framework: 'OWASP',
                         time: '1 hour ago',
                         status: 'fixed'
                       },
                       { 
                         file: 'database/user.rb', 
                         violation: 'GDPR - Inadequate data retention', 
                         severity: 'medium', 
                         framework: 'GDPR',
                         time: '2 hours ago',
                         status: 'reviewing'
                       },
                       { 
                         file: 'config/server.go', 
                         violation: 'NIST - Missing security headers', 
                         severity: 'medium', 
                         framework: 'NIST',
                         time: '4 hours ago',
                         status: 'fixed'
                       },
                       { 
                         file: 'utils/encryption.java', 
                         violation: 'ISO 27001 - Weak encryption algorithm', 
                         severity: 'high', 
                         framework: 'ISO 27001',
                         time: '6 hours ago',
                         status: 'remediating'
                       }
                     ].map((violation, index) => (
                       <div key={index} className={`
                         p-3 rounded-lg border
                         ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                       `}>
                         <div className="flex items-start justify-between mb-2">
                           <div className="flex-1">
                             <h4 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                               {violation.file}
                             </h4>
                             <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                               {violation.violation}
                             </p>
                           </div>
                           <Badge variant="outline" className={
                             violation.severity === 'critical' ? 'text-red-400 border-red-400' :
                             violation.severity === 'high' ? 'text-orange-400 border-orange-400' :
                             'text-blue-400 border-blue-400'
                           }>
                             {violation.severity}
                           </Badge>
                         </div>
                         <div className="flex items-center justify-between text-xs">
                           <div className="flex items-center space-x-2">
                             <Badge variant="secondary" className="text-xs">
                               {violation.framework}
                             </Badge>
                             <Badge variant="outline" className={
                               violation.status === 'fixed' ? 'text-green-400 border-green-400' :
                               violation.status === 'remediating' ? 'text-orange-400 border-orange-400' :
                               'text-blue-400 border-blue-400'
                             }>
                               {violation.status}
                             </Badge>
                           </div>
                           <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                             {violation.time}
                           </span>
                         </div>
                       </div>
                     ))}
                   </div>
                 </CardContent>
               </Card>

               {/* Automated Policy Enforcement */}
               <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                 <CardHeader>
                   <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                     <Wrench className="w-5 h-5 mr-2 text-green-400" />
                     Automated Policy Enforcement
                   </CardTitle>
                   <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                     Real-time policy enforcement and automated remediation
                   </CardDescription>
                 </CardHeader>
                 <CardContent>
                   <div className="space-y-6">
                     {/* Enforcement Stats */}
                     <div className="grid grid-cols-2 gap-4">
                       {[
                         { label: 'Auto-Enforced', value: '823', percentage: 97, color: 'text-green-400' },
                         { label: 'Manual Review', value: '24', percentage: 3, color: 'text-orange-400' }
                       ].map((stat, index) => (
                         <div key={index} className={`text-center p-3 rounded ${isDark ? 'bg-zinc-800/50' : 'bg-gray-100'}`}>
                           <div className={`text-xl font-bold ${stat.color}`}>
                             {stat.value}
                           </div>
                           <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                             {stat.label} ({stat.percentage}%)
                           </div>
                         </div>
                       ))}
                     </div>

                     {/* Enforcement Actions */}
                     <div>
                       <h4 className={`font-semibold text-sm mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                         Recent Enforcement Actions
                       </h4>
                       <div className="space-y-3">
                         {[
                           { action: 'Blocked insecure API call', policy: 'Encryption Standards', time: '2 min ago', type: 'block' },
                           { action: 'Auto-fixed weak password hash', policy: 'Authentication', time: '8 min ago', type: 'fix' },
                           { action: 'Flagged PII exposure', policy: 'Data Protection', time: '15 min ago', type: 'alert' },
                           { action: 'Applied security headers', policy: 'Network Security', time: '23 min ago', type: 'fix' },
                           { action: 'Quarantined vulnerable dependency', policy: 'Third-Party Risk', time: '31 min ago', type: 'quarantine' }
                         ].map((action, index) => (
                           <div key={index} className={`
                             p-3 rounded-lg border
                             ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                           `}>
                             <div className="flex items-center justify-between">
                               <div className="flex-1">
                                 <h5 className={`font-semibold text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                                   {action.action}
                                 </h5>
                                 <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                                   Policy: {action.policy}
                                 </p>
                               </div>
                               <div className="text-right">
                                 <Badge variant="outline" className={
                                   action.type === 'fix' ? 'text-green-400 border-green-400' :
                                   action.type === 'block' ? 'text-red-400 border-red-400' :
                                   action.type === 'quarantine' ? 'text-orange-400 border-orange-400' :
                                   'text-blue-400 border-blue-400'
                                 }>
                                   {action.type}
                                 </Badge>
                                 <p className={`text-xs mt-1 ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                                   {action.time}
                                 </p>
                               </div>
                             </div>
                           </div>
                         ))}
                       </div>
                     </div>
                   </div>
                 </CardContent>
               </Card>
             </div>
           </div>
         </TabsContent>
      </Tabs>
    </div>
  );
};

export default SecurityManager;
