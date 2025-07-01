// src/components/projects/GitHubIntegration.jsx
// GitHub OAuth Integration & Repository Management - v4.2.0
"use client"

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { 
  Github,
  GitBranch,
  Settings,
  Key,
  Webhook,
  Users,
  Star,
  GitCommit,
  Lock,
  Unlock,
  CheckCircle,
  AlertTriangle,
  Clock,
  ExternalLink,
  RefreshCw,
  Plus,
  Trash2,
  Eye,
  Code,
  Shield,
  Activity,
  Download,
  Upload,
  Link,
  Globe
} from 'lucide-react';
import { useTheme } from '../darkmode/ThemeProvider';

// Mock GitHub data
const GITHUB_CONNECTION = {
  isConnected: false,
  user: null,
  accessToken: null,
  scopes: ['repo', 'read:user', 'admin:repo_hook'],
  connectedAt: null,
  lastSync: null
};

const GITHUB_REPOSITORIES = [
  {
    id: 'repo_001',
    name: 'ai-guardian-core',
    fullName: 'company/ai-guardian-core',
    description: 'Core AI security scanning engine',
    private: true,
    language: 'Python',
    stars: 127,
    forks: 23,
    watchers: 45,
    size: 2345,
    defaultBranch: 'main',
    branches: ['main', 'development', 'feature/auth', 'hotfix/security'],
    lastCommit: '2024-01-15T10:30:00Z',
    lastPush: '2024-01-15T09:45:00Z',
    webhookConfigured: true,
    scanningEnabled: true,
    autoFixEnabled: true,
    vulnerabilities: 12,
    lastScan: '2024-01-15T08:30:00Z',
    scanStatus: 'completed'
  },
  {
    id: 'repo_002',
    name: 'frontend-dashboard',
    fullName: 'company/frontend-dashboard',
    description: 'React-based security dashboard',
    private: false,
    language: 'JavaScript',
    stars: 89,
    forks: 15,
    watchers: 32,
    size: 1876,
    defaultBranch: 'main',
    branches: ['main', 'develop', 'feature/ui-updates'],
    lastCommit: '2024-01-15T11:15:00Z',
    lastPush: '2024-01-15T10:20:00Z',
    webhookConfigured: false,
    scanningEnabled: false,
    autoFixEnabled: false,
    vulnerabilities: 5,
    lastScan: null,
    scanStatus: 'pending'
  }
];

const WEBHOOK_EVENTS = [
  { event: 'push', enabled: true, description: 'Triggered when code is pushed to repository' },
  { event: 'pull_request', enabled: true, description: 'Triggered when pull requests are opened/updated' },
  { event: 'release', enabled: false, description: 'Triggered when releases are published' },
  { event: 'issues', enabled: true, description: 'Triggered when issues are created/updated' },
  { event: 'commit_comment', enabled: false, description: 'Triggered when commit comments are added' }
];

const GitHubIntegration = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('connection');
  const [githubConnection, setGithubConnection] = useState(GITHUB_CONNECTION);
  const [repositories, setRepositories] = useState(GITHUB_REPOSITORIES);
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [webhookEvents, setWebhookEvents] = useState(WEBHOOK_EVENTS);
  const [isConnecting, setIsConnecting] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  // Simulate GitHub OAuth connection
  const connectToGitHub = async () => {
    setIsConnecting(true);
    
    // Simulate OAuth flow
    setTimeout(() => {
      setGithubConnection({
        isConnected: true,
        user: {
          login: 'developer',
          name: 'John Developer',
          email: 'john@company.com',
          avatar_url: 'https://github.com/identicons/developer.png',
          public_repos: 15,
          followers: 234,
          following: 89
        },
        accessToken: 'ghp_xxxxxxxxxxxxxxxxxxxx',
        scopes: ['repo', 'read:user', 'admin:repo_hook'],
        connectedAt: new Date().toISOString(),
        lastSync: new Date().toISOString()
      });
      setIsConnecting(false);
    }, 2000);
  };

  const disconnectFromGitHub = () => {
    setGithubConnection(GITHUB_CONNECTION);
    setRepositories([]);
  };

  const toggleRepoScanning = (repoId) => {
    setRepositories(repos => repos.map(repo => 
      repo.id === repoId 
        ? { ...repo, scanningEnabled: !repo.scanningEnabled }
        : repo
    ));
  };

  const toggleWebhook = (repoId) => {
    setRepositories(repos => repos.map(repo => 
      repo.id === repoId 
        ? { ...repo, webhookConfigured: !repo.webhookConfigured }
        : repo
    ));
  };

  const scanRepository = (repoId) => {
    setRepositories(repos => repos.map(repo => 
      repo.id === repoId 
        ? { ...repo, scanStatus: 'scanning', lastScan: new Date().toISOString() }
        : repo
    ));
    
    // Simulate scan completion
    setTimeout(() => {
      setRepositories(repos => repos.map(repo => 
        repo.id === repoId 
          ? { ...repo, scanStatus: 'completed', vulnerabilities: Math.floor(Math.random() * 20) }
          : repo
      ));
    }, 3000);
  };

  const toggleWebhookEvent = (eventName) => {
    setWebhookEvents(events => events.map(event =>
      event.event === eventName
        ? { ...event, enabled: !event.enabled }
        : event
    ));
  };

  const filteredRepositories = repositories.filter(repo =>
    repo.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    repo.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            GitHub Integration
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Connect and manage your GitHub repositories for automated security scanning
          </p>
        </div>
        <div className="flex items-center space-x-3">
          {githubConnection.isConnected ? (
            <Badge variant="outline" className="text-green-400 border-green-400">
              <Github className="w-3 h-3 mr-1" />
              Connected
            </Badge>
          ) : (
            <Badge variant="outline" className="text-gray-400 border-gray-400">
              Not Connected
            </Badge>
          )}
          <Button variant="outline" size="sm">
            <ExternalLink className="h-4 w-4 mr-2" />
            GitHub Settings
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-4 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="connection">
            <Github className="w-4 h-4 mr-2" />
            Connection
          </TabsTrigger>
          <TabsTrigger value="repositories">
            <GitBranch className="w-4 h-4 mr-2" />
            Repositories
          </TabsTrigger>
          <TabsTrigger value="webhooks">
            <Webhook className="w-4 h-4 mr-2" />
            Webhooks
          </TabsTrigger>
          <TabsTrigger value="settings">
            <Settings className="w-4 h-4 mr-2" />
            Settings
          </TabsTrigger>
        </TabsList>

        {/* Connection Tab */}
        <TabsContent value="connection" className="space-y-6 mt-6">
          {!githubConnection.isConnected ? (
            /* Not Connected State */
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader className="text-center">
                <Github className="w-16 h-16 mx-auto mb-4 text-gray-400" />
                <CardTitle className={`${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  Connect to GitHub
                </CardTitle>
                <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Connect your GitHub account to enable repository scanning and automated security monitoring
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    Required Permissions
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {[
                      { permission: 'repo', description: 'Access to repository content and metadata' },
                      { permission: 'read:user', description: 'Read user profile information' },
                      { permission: 'admin:repo_hook', description: 'Manage repository webhooks' }
                    ].map((perm, index) => (
                      <div key={index} className={`
                        p-3 rounded-lg border
                        ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                      `}>
                        <div className="flex items-center space-x-2 mb-2">
                          <Key className="w-4 h-4 text-blue-400" />
                          <span className={`font-medium ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                            {perm.permission}
                          </span>
                        </div>
                        <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          {perm.description}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="text-center">
                  <Button 
                    onClick={connectToGitHub}
                    disabled={isConnecting}
                    size="lg"
                    className="w-full md:w-auto"
                  >
                    {isConnecting ? (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                        Connecting...
                      </>
                    ) : (
                      <>
                        <Github className="w-4 h-4 mr-2" />
                        Connect with GitHub
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            /* Connected State */
            <div className="space-y-6">
              {/* User Information */}
              <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
                <CardHeader>
                  <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    <CheckCircle className="w-5 h-5 mr-2 text-green-400" />
                    GitHub Account Connected
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center space-x-4">
                    <img 
                      src={githubConnection.user.avatar_url} 
                      alt="GitHub Avatar"
                      className="w-16 h-16 rounded-full"
                    />
                    <div className="flex-1">
                      <h3 className={`text-lg font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        {githubConnection.user.name}
                      </h3>
                      <p className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        @{githubConnection.user.login}
                      </p>
                      <p className={`text-sm ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                        {githubConnection.user.email}
                      </p>
                    </div>
                    <div className="text-right">
                      <div className="grid grid-cols-3 gap-4 text-center">
                        <div>
                          <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {githubConnection.user.public_repos}
                          </div>
                          <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            Repos
                          </div>
                        </div>
                        <div>
                          <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {githubConnection.user.followers}
                          </div>
                          <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            Followers
                          </div>
                        </div>
                        <div>
                          <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {githubConnection.user.following}
                          </div>
                          <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            Following
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="mt-6 pt-4 border-t border-zinc-700">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Connected:
                        </span>
                        <span className={`ml-2 ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                          {new Date(githubConnection.connectedAt).toLocaleString()}
                        </span>
                      </div>
                      <div>
                        <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Last Sync:
                        </span>
                        <span className={`ml-2 ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                          {new Date(githubConnection.lastSync).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex justify-between items-center mt-4">
                      <div className="flex space-x-2">
                        {githubConnection.scopes.map((scope, index) => (
                          <Badge key={index} variant="outline" className="text-blue-400 border-blue-400">
                            {scope}
                          </Badge>
                        ))}
                      </div>
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={disconnectFromGitHub}
                      >
                        <Trash2 className="w-3 h-3 mr-1" />
                        Disconnect
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Connection Stats */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { title: 'Repositories Scanned', value: repositories.filter(r => r.scanningEnabled).length, icon: GitBranch },
                  { title: 'Webhooks Active', value: repositories.filter(r => r.webhookConfigured).length, icon: Webhook },
                  { title: 'Total Vulnerabilities', value: repositories.reduce((sum, r) => sum + r.vulnerabilities, 0), icon: Shield }
                ].map((stat, index) => (
                  <Card key={index} className={`
                    ${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}
                  `}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {stat.title}
                          </p>
                          <p className={`text-2xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                            {stat.value}
                          </p>
                        </div>
                        <stat.icon className="w-8 h-8 text-blue-400" />
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </TabsContent>

        {/* Repositories Tab */}
        <TabsContent value="repositories" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    <GitBranch className="w-5 h-5 mr-2 text-blue-400" />
                    Repository Management
                  </CardTitle>
                  <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Manage scanning and monitoring for your GitHub repositories
                  </CardDescription>
                </div>
                <Button variant="outline" size="sm">
                  <RefreshCw className="w-3 h-3 mr-1" />
                  Sync Repositories
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {/* Search */}
              <div className="mb-6">
                <Input
                  placeholder="Search repositories..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className={isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white'}
                />
              </div>

              {/* Repository List */}
              <div className="space-y-4">
                {filteredRepositories.map((repo) => (
                  <div key={repo.id} className={`
                    p-4 rounded-lg border
                    ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                  `}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <div className="flex items-center space-x-2">
                          {repo.private ? (
                            <Lock className="w-4 h-4 text-orange-400" />
                          ) : (
                            <Unlock className="w-4 h-4 text-green-400" />
                          )}
                          <div>
                            <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                              {repo.name}
                            </h4>
                            <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                              {repo.description}
                            </p>
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-3">
                        <Badge variant="outline">
                          {repo.language}
                        </Badge>
                        <div className="flex items-center space-x-1 text-sm text-gray-400">
                          <Star className="w-3 h-3" />
                          <span>{repo.stars}</span>
                        </div>
                        <Badge variant="outline" className={
                          repo.scanStatus === 'completed' ? 'text-green-400 border-green-400' :
                          repo.scanStatus === 'scanning' ? 'text-orange-400 border-orange-400' :
                          'text-gray-400 border-gray-400'
                        }>
                          {repo.scanStatus}
                        </Badge>
                      </div>
                    </div>

                    <div className="mt-4 flex items-center justify-between">
                      <div className="flex items-center space-x-4 text-sm">
                        <div>
                          <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            Vulnerabilities:
                          </span>
                          <span className={`ml-1 font-semibold ${
                            repo.vulnerabilities > 10 ? 'text-red-400' : 
                            repo.vulnerabilities > 5 ? 'text-orange-400' : 
                            'text-green-400'
                          }`}>
                            {repo.vulnerabilities}
                          </span>
                        </div>
                        <div>
                          <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            Last commit:
                          </span>
                          <span className={`ml-1 ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                            {new Date(repo.lastCommit).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                      
                      <div className="flex space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => scanRepository(repo.id)}
                          disabled={repo.scanStatus === 'scanning'}
                        >
                          {repo.scanStatus === 'scanning' ? (
                            <>
                              <RefreshCw className="w-3 h-3 mr-1 animate-spin" />
                              Scanning...
                            </>
                          ) : (
                            <>
                              <Shield className="w-3 h-3 mr-1" />
                              Scan Now
                            </>
                          )}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => toggleWebhook(repo.id)}
                        >
                          {repo.webhookConfigured ? (
                            <>
                              <Webhook className="w-3 h-3 mr-1 text-green-400" />
                              Webhook On
                            </>
                          ) : (
                            <>
                              <Webhook className="w-3 h-3 mr-1" />
                              Setup Webhook
                            </>
                          )}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => toggleRepoScanning(repo.id)}
                        >
                          {repo.scanningEnabled ? (
                            <>
                              <Activity className="w-3 h-3 mr-1 text-green-400" />
                              Monitoring On
                            </>
                          ) : (
                            <>
                              <Activity className="w-3 h-3 mr-1" />
                              Enable Monitoring
                            </>
                          )}
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Webhooks Tab */}
        <TabsContent value="webhooks" className="mt-6">
          <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
            <CardHeader>
              <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                <Webhook className="w-5 h-5 mr-2 text-blue-400" />
                Webhook Configuration
              </CardTitle>
              <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                Configure webhook events for real-time repository monitoring
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h4 className={`font-semibold mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      Webhook URL
                    </h4>
                    <div className={`
                      p-3 rounded-lg border font-mono text-sm
                      ${isDark ? 'border-zinc-700 bg-zinc-800/30 text-zinc-300' : 'border-gray-200 bg-gray-50 text-gray-700'}
                    `}>
                      https://api.aiguardian.com/webhooks/github
                    </div>
                  </div>
                  <div>
                    <h4 className={`font-semibold mb-3 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      Content Type
                    </h4>
                    <div className={`
                      p-3 rounded-lg border font-mono text-sm
                      ${isDark ? 'border-zinc-700 bg-zinc-800/30 text-zinc-300' : 'border-gray-200 bg-gray-50 text-gray-700'}
                    `}>
                      application/json
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className={`font-semibold mb-4 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    Event Configuration
                  </h4>
                  <div className="space-y-3">
                    {webhookEvents.map((event) => (
                      <div key={event.event} className={`
                        p-4 rounded-lg border flex items-center justify-between
                        ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}
                      `}>
                        <div>
                          <div className="flex items-center space-x-3">
                            <h5 className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                              {event.event}
                            </h5>
                            <Badge variant="outline" className={
                              event.enabled ? 'text-green-400 border-green-400' : 'text-gray-400 border-gray-400'
                            }>
                              {event.enabled ? 'Enabled' : 'Disabled'}
                            </Badge>
                          </div>
                          <p className={`text-sm mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                            {event.description}
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => toggleWebhookEvent(event.event)}
                        >
                          {event.enabled ? 'Disable' : 'Enable'}
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Settings Tab */}
        <TabsContent value="settings" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Settings className="w-5 h-5 mr-2 text-gray-400" />
                  General Settings
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        Auto-scan new repositories
                      </h4>
                      <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        Automatically enable scanning for newly connected repositories
                      </p>
                    </div>
                    <Button variant="outline" size="sm">
                      Enable
                    </Button>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        Real-time notifications
                      </h4>
                      <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        Send notifications for vulnerability discoveries
                      </p>
                    </div>
                    <Button variant="outline" size="sm">
                      Configure
                    </Button>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className={`font-medium ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                        Sync frequency
                      </h4>
                      <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        How often to sync repository data
                      </p>
                    </div>
                    <select className={`
                      px-3 py-1 rounded border text-sm
                      ${isDark ? 'bg-zinc-800 border-zinc-700 text-zinc-100' : 'bg-white border-gray-300'}
                    `}>
                      <option>Every hour</option>
                      <option>Every 6 hours</option>
                      <option>Daily</option>
                    </select>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
              <CardHeader>
                <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  <Key className="w-5 h-5 mr-2 text-yellow-400" />
                  API Configuration
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <h4 className={`font-medium mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      Access Token
                    </h4>
                    <div className={`
                      p-3 rounded-lg border font-mono text-sm
                      ${isDark ? 'border-zinc-700 bg-zinc-800/30 text-zinc-300' : 'border-gray-200 bg-gray-50 text-gray-700'}
                    `}>
                      ghp_••••••••••••••••••••
                    </div>
                  </div>
                  
                  <div>
                    <h4 className={`font-medium mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      Rate Limiting
                    </h4>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Remaining:
                        </span>
                        <span className={`ml-2 font-medium ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                          4,847
                        </span>
                      </div>
                      <div>
                        <span className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                          Resets at:
                        </span>
                        <span className={`ml-2 font-medium ${isDark ? 'text-zinc-200' : 'text-gray-800'}`}>
                          15:32
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <Button variant="outline" className="w-full">
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh Token
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default GitHubIntegration; 