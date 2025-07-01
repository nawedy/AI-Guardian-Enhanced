// src/components/security/LanguageSupport.jsx
// Language Support Management Component - v4.2.0
"use client"

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { 
  Code, 
  Brain, 
  CheckCircle, 
  Settings,
  Download,
  Upload,
  RefreshCw,
  Wrench,
  Shield,
  Activity
} from 'lucide-react';
import { useTheme } from '../darkmode/ThemeProvider';

const LANGUAGE_DETAILS = {
  python: {
    name: 'Python',
    icon: '🐍',
    version: '3.12+',
    coverage: 98,
    scanEngine: 'bandit-pro',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['SQL Injection', 'XSS', 'Deserialization', 'Path Traversal'],
    frameworks: ['Django', 'Flask', 'FastAPI', 'Tornado'],
    rules: 147,
    lastUpdated: '2024-01-15'
  },
  javascript: {
    name: 'JavaScript',
    icon: '🟨',
    version: 'ES2024',
    coverage: 95,
    scanEngine: 'eslint-security-pro',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['XSS', 'Prototype Pollution', 'Injection', 'CSRF'],
    frameworks: ['React', 'Vue', 'Angular', 'Node.js'],
    rules: 134,
    lastUpdated: '2024-01-14'
  },
  typescript: {
    name: 'TypeScript',
    icon: '🔷',
    version: '5.3+',
    coverage: 96,
    scanEngine: 'ts-security-pro',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['Type Confusion', 'Injection', 'XSS', 'Prototype Pollution'],
    frameworks: ['React', 'Vue', 'Angular', 'Nest.js'],
    rules: 142,
    lastUpdated: '2024-01-15'
  },
  java: {
    name: 'Java',
    icon: '☕',
    version: '21 LTS',
    coverage: 94,
    scanEngine: 'spotbugs-security',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['Injection', 'Deserialization', 'XXE', 'Path Traversal'],
    frameworks: ['Spring', 'Hibernate', 'Struts', 'JSF'],
    rules: 156,
    lastUpdated: '2024-01-13'
  },
  csharp: {
    name: 'C#',
    icon: '💜',
    version: '.NET 8',
    coverage: 93,
    scanEngine: 'security-code-scan',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['Injection', 'XSS', 'Deserialization', 'Weak Crypto'],
    frameworks: ['.NET Core', 'ASP.NET', 'Entity Framework', 'Blazor'],
    rules: 128,
    lastUpdated: '2024-01-14'
  },
  go: {
    name: 'Go',
    icon: '🔵',
    version: '1.21+',
    coverage: 91,
    scanEngine: 'gosec-pro',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['Injection', 'Path Traversal', 'Weak Crypto', 'Race Conditions'],
    frameworks: ['Gin', 'Echo', 'Fiber', 'GORM'],
    rules: 98,
    lastUpdated: '2024-01-12'
  },
  rust: {
    name: 'Rust',
    icon: '🦀',
    version: '1.75+',
    coverage: 89,
    scanEngine: 'cargo-audit-pro',
    aiSupport: true,
    autoRemediation: false,
    vulnerabilities: ['Unsafe Code', 'Dependency Issues', 'Memory Safety', 'Logic Bugs'],
    frameworks: ['Actix', 'Rocket', 'Warp', 'Tokio'],
    rules: 87,
    lastUpdated: '2024-01-10'
  },
  php: {
    name: 'PHP',
    icon: '🐘',
    version: '8.3+',
    coverage: 92,
    scanEngine: 'psalm-security',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['Injection', 'XSS', 'File Inclusion', 'Weak Crypto'],
    frameworks: ['Laravel', 'Symfony', 'CodeIgniter', 'Zend'],
    rules: 119,
    lastUpdated: '2024-01-13'
  },
  ruby: {
    name: 'Ruby',
    icon: '💎',
    version: '3.3+',
    coverage: 90,
    scanEngine: 'brakeman-pro',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['Injection', 'XSS', 'CSRF', 'Mass Assignment'],
    frameworks: ['Rails', 'Sinatra', 'Hanami', 'Grape'],
    rules: 104,
    lastUpdated: '2024-01-11'
  },
  kotlin: {
    name: 'Kotlin',
    icon: '🟣',
    version: '1.9+',
    coverage: 88,
    scanEngine: 'detekt-security',
    aiSupport: true,
    autoRemediation: true,
    vulnerabilities: ['Injection', 'Deserialization', 'Weak Crypto', 'Null Safety'],
    frameworks: ['Spring Boot', 'Ktor', 'Android', 'Exposed'],
    rules: 92,
    lastUpdated: '2024-01-09'
  }
};

const LanguageSupport = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [selectedLanguage, setSelectedLanguage] = useState('python');

  const selectedLang = LANGUAGE_DETAILS[selectedLanguage];

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Language Overview Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        {Object.entries(LANGUAGE_DETAILS).map(([key, lang]) => (
          <Card
            key={key}
            className={`
              cursor-pointer transition-all duration-200 hover:scale-105
              ${selectedLanguage === key 
                ? 'ring-2 ring-blue-400 border-blue-400' 
                : isDark ? 'border-zinc-700 bg-zinc-800/50 hover:border-zinc-600' : 'border-gray-200 bg-gray-50 hover:border-gray-300'
              }
            `}
            onClick={() => setSelectedLanguage(key)}
          >
            <CardHeader className="pb-3">
              <div className="flex items-center space-x-2">
                <span className="text-2xl">{lang.icon}</span>
                <div>
                  <CardTitle className={`text-sm ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {lang.name}
                  </CardTitle>
                  <p className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-500'}`}>
                    {lang.version}
                  </p>
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className={isDark ? 'text-zinc-400' : 'text-gray-600'}>Coverage</span>
                  <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{lang.coverage}%</span>
                </div>
                <Progress value={lang.coverage} className="h-1" />
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1">
                    {lang.aiSupport && <Brain className="w-3 h-3 text-purple-400" />}
                    {lang.autoRemediation && <Wrench className="w-3 h-3 text-green-400" />}
                  </div>
                  <Badge variant="outline" size="sm" className="text-xs">
                    {lang.rules} rules
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Selected Language Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Language Configuration */}
        <Card className={`lg:col-span-2 ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="text-3xl">{selectedLang.icon}</span>
                <div>
                  <CardTitle className={`${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {selectedLang.name} Configuration
                  </CardTitle>
                  <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Security scanning configuration for {selectedLang.name} {selectedLang.version}
                  </CardDescription>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Badge variant="outline" className="text-green-400 border-green-400">
                  {selectedLang.coverage}% Coverage
                </Badge>
                <Button variant="outline" size="sm">
                  <Settings className="w-4 h-4 mr-2" />
                  Configure
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Scan Engine */}
            <div>
              <h4 className={`font-semibold mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                Scan Engine
              </h4>
              <div className={`p-3 rounded-lg border ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Shield className="w-4 h-4 text-blue-400" />
                    <span className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      {selectedLang.scanEngine}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge variant="outline" className="text-xs">
                      {selectedLang.rules} rules active
                    </Badge>
                    <Button variant="outline" size="sm">
                      <RefreshCw className="w-3 h-3 mr-1" />
                      Update
                    </Button>
                  </div>
                </div>
              </div>
            </div>

            {/* Supported Vulnerabilities */}
            <div>
              <h4 className={`font-semibold mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                Detected Vulnerability Types
              </h4>
              <div className="grid grid-cols-2 gap-2">
                {selectedLang.vulnerabilities.map((vuln, index) => (
                  <div key={index} className={`
                    p-2 rounded border text-sm
                    ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-3 h-3 text-green-400" />
                      <span className={isDark ? 'text-zinc-300' : 'text-gray-700'}>{vuln}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Supported Frameworks */}
            <div>
              <h4 className={`font-semibold mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                Supported Frameworks
              </h4>
              <div className="flex flex-wrap gap-2">
                {selectedLang.frameworks.map((framework, index) => (
                  <Badge key={index} variant="secondary" className="text-xs">
                    {framework}
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Language Statistics */}
        <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
          <CardHeader>
            <CardTitle className={`${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
              Language Statistics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              {[
                { label: 'Total Scans', value: '1,247', icon: Activity },
                { label: 'Issues Found', value: '89', icon: Shield },
                { label: 'AI Fixes', value: '67', icon: Brain },
                { label: 'Success Rate', value: '94%', icon: CheckCircle }
              ].map((stat, index) => (
                <div key={index} className={`
                  p-3 rounded-lg border
                  ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                `}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <stat.icon className="w-4 h-4 text-blue-400" />
                      <span className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        {stat.label}
                      </span>
                    </div>
                    <span className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      {stat.value}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-4 border-t border-zinc-700">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Last Updated
                  </span>
                  <span className={`text-sm ${isDark ? 'text-zinc-300' : 'text-gray-700'}`}>
                    {selectedLang.lastUpdated}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  {selectedLang.aiSupport && (
                    <Badge variant="outline" className="text-purple-400 border-purple-400 text-xs">
                      <Brain className="w-3 h-3 mr-1" />
                      AI Enhanced
                    </Badge>
                  )}
                  {selectedLang.autoRemediation && (
                    <Badge variant="outline" className="text-green-400 border-green-400 text-xs">
                      <Wrench className="w-3 h-3 mr-1" />
                      Auto-Fix
                    </Badge>
                  )}
                </div>
              </div>
            </div>

            <div className="pt-4 space-y-2">
              <Button variant="outline" size="sm" className="w-full">
                <Download className="w-4 h-4 mr-2" />
                Export Rules
              </Button>
              <Button variant="outline" size="sm" className="w-full">
                <Upload className="w-4 h-4 mr-2" />
                Import Custom Rules
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default LanguageSupport;
