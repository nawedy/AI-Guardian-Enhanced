"use client"

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { 
  MessageSquare, 
  Settings, 
  Hash, 
  Users, 
  Bell, 
  Send, 
  CheckCircle, 
  AlertTriangle,
  Clock,
  RefreshCw,
  Plus,
  Edit,
  ExternalLink,
  Volume2,
  VolumeX,
  Eye,
  UserPlus,
  Filter
} from 'lucide-react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

/**
 * Mock Slack Data
 */
const MOCK_CHANNELS = [
  {
    id: 'C001',
    name: 'security-alerts',
    description: 'Critical security notifications and alerts',
    type: 'public',
    members: 15,
    notifications: true,
    lastActivity: '2 minutes ago',
    messageCount: 247,
    purpose: 'Security team notifications'
  },
  {
    id: 'C002',
    name: 'vulnerability-reports',
    description: 'Automated vulnerability scan reports',
    type: 'private',
    members: 8,
    notifications: true,
    lastActivity: '5 minutes ago',
    messageCount: 134,
    purpose: 'Vulnerability tracking and remediation'
  },
  {
    id: 'C003',
    name: 'general',
    description: 'General team discussions',
    type: 'public',
    members: 28,
    notifications: false,
    lastActivity: '1 hour ago',
    messageCount: 892,
    purpose: 'General team communication'
  },
  {
    id: 'C004',
    name: 'incident-response',
    description: 'Emergency incident response coordination',
    type: 'private',
    members: 12,
    notifications: true,
    lastActivity: '3 hours ago',
    messageCount: 56,
    purpose: 'Incident management and coordination'
  }
];

const MOCK_NOTIFICATIONS = [
  {
    id: 'N001',
    type: 'vulnerability',
    title: 'Critical SQL Injection Found',
    message: '🚨 Critical vulnerability detected in authentication module. Immediate attention required.',
    channel: '#security-alerts',
    timestamp: '2024-01-16T14:30:00Z',
    status: 'sent',
    priority: 'critical'
  },
  {
    id: 'N002',
    type: 'scan-complete',
    title: 'Security Scan Completed',
    message: '✅ Weekly security scan completed. 3 new issues found, 5 resolved.',
    channel: '#vulnerability-reports',
    timestamp: '2024-01-16T12:00:00Z',
    status: 'sent',
    priority: 'info'
  },
  {
    id: 'N003',
    type: 'system-alert',
    title: 'High CPU Usage Alert',
    message: '⚠️ CPU usage above 80% on production server for 5+ minutes.',
    channel: '#security-alerts',
    timestamp: '2024-01-16T10:45:00Z',
    status: 'failed',
    priority: 'warning'
  }
];

/**
 * Slack Configuration Component
 */
const SlackConfiguration = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [config, setConfig] = useState({
    workspaceUrl: 'https://aiGuardian.slack.com',
    botToken: 'xoxb-••••••••••••••••••••••••••••••••',
    webhookUrl: 'https://hooks.slack.com/services/••••••••••••••••••••••••••••••••',
    defaultChannel: '#security-alerts',
    enableNotifications: true,
    enableDirectMessages: false,
    notificationTypes: {
      vulnerabilities: true,
      scanResults: true,
      systemAlerts: true,
      maintenanceUpdates: false
    },
    messageFormat: 'detailed'
  });

  const handleSave = () => {
    console.log('Saving Slack configuration:', config);
  };

  return (
    <Card className={`
      transition-all duration-300
      ${isDark 
        ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
        : 'border-gray-200 bg-white/80 backdrop-blur-sm'
      }
    `}>
      <CardHeader>
        <CardTitle className={`
          flex items-center transition-colors
          ${isDark ? 'text-zinc-100' : 'text-gray-900'}
        `}>
          <Settings className="w-5 h-5 mr-2" />
          Slack Configuration
        </CardTitle>
        <CardDescription className={`
          transition-colors
          ${isDark ? 'text-zinc-400' : 'text-gray-600'}
        `}>
          Configure your Slack workspace integration and notification settings
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Workspace URL
              </Label>
              <Input
                value={config.workspaceUrl}
                onChange={(e) => setConfig({...config, workspaceUrl: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Bot Token
              </Label>
              <Input
                type="password"
                value={config.botToken}
                onChange={(e) => setConfig({...config, botToken: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Webhook URL
              </Label>
              <Input
                type="password"
                value={config.webhookUrl}
                onChange={(e) => setConfig({...config, webhookUrl: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Default Channel
              </Label>
              <Select value={config.defaultChannel} onValueChange={(value) => setConfig({...config, defaultChannel: value})}>
                <SelectTrigger className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="#security-alerts">#security-alerts</SelectItem>
                  <SelectItem value="#vulnerability-reports">#vulnerability-reports</SelectItem>
                  <SelectItem value="#general">#general</SelectItem>
                  <SelectItem value="#incident-response">#incident-response</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div className="space-y-4">
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Message Format
              </Label>
              <Select value={config.messageFormat} onValueChange={(value) => setConfig({...config, messageFormat: value})}>
                <SelectTrigger className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="minimal">Minimal</SelectItem>
                  <SelectItem value="detailed">Detailed</SelectItem>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                  Enable Notifications
                </Label>
                <Switch
                  checked={config.enableNotifications}
                  onCheckedChange={(checked) => setConfig({...config, enableNotifications: checked})}
                />
              </div>
              
              <div className="flex items-center justify-between">
                <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                  Enable Direct Messages
                </Label>
                <Switch
                  checked={config.enableDirectMessages}
                  onCheckedChange={(checked) => setConfig({...config, enableDirectMessages: checked})}
                />
              </div>
            </div>
            
            <div className="space-y-3">
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Notification Types
              </Label>
              {Object.entries(config.notificationTypes).map(([type, enabled]) => (
                <div key={type} className="flex items-center justify-between">
                  <Label className={`text-xs ${isDark ? 'text-zinc-300' : 'text-gray-600'}`}>
                    {type.charAt(0).toUpperCase() + type.slice(1).replace(/([A-Z])/g, ' $1')}
                  </Label>
                  <Switch
                    checked={enabled}
                    onCheckedChange={(checked) => setConfig({
                      ...config,
                      notificationTypes: { ...config.notificationTypes, [type]: checked }
                    })}
                  />
                </div>
              ))}
            </div>
          </div>
        </div>
        
        <div className="flex items-center space-x-3 pt-4 border-t border-zinc-700">
          <Button onClick={handleSave} className="bg-blue-600 hover:bg-blue-700 text-white">
            Save Configuration
          </Button>
          <Button variant="outline" className={`
            ${isDark 
              ? 'border-zinc-700 text-zinc-300 hover:bg-zinc-800' 
              : 'border-gray-300 text-gray-700 hover:bg-gray-50'
            }
          `}>
            Test Connection
          </Button>
          <Button variant="outline" className={`
            ${isDark 
              ? 'border-zinc-700 text-zinc-300 hover:bg-zinc-800' 
              : 'border-gray-300 text-gray-700 hover:bg-gray-50'
            }
          `}>
            Send Test Message
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Channel Management Component
 */
const ChannelManagement = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [channels, setChannels] = useState(MOCK_CHANNELS);
  const [filter, setFilter] = useState('all');

  const getTypeColor = (type) => {
    switch (type) {
      case 'public': return 'text-green-400 border-green-400 bg-green-500/10';
      case 'private': return 'text-orange-400 border-orange-400 bg-orange-500/10';
      default: return 'text-gray-400 border-gray-400 bg-gray-500/10';
    }
  };

  const filteredChannels = channels.filter(channel => {
    return filter === 'all' || channel.type === filter;
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className={`text-lg font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
          Slack Channels
        </h3>
        <div className="flex items-center space-x-3">
          <Select value={filter} onValueChange={setFilter}>
            <SelectTrigger className={`w-32 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="public">Public</SelectItem>
              <SelectItem value="private">Private</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white">
            <Plus className="w-4 h-4 mr-2" />
            Add Channel
          </Button>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {filteredChannels.map((channel) => (
          <Card key={channel.id} className={`
            transition-all duration-300 hover:scale-[1.02]
            ${isDark 
              ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
              : 'border-gray-200 bg-white/80 backdrop-blur-sm'
            }
          `}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Hash className={`w-4 h-4 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`} />
                  <CardTitle className={`text-base font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {channel.name}
                  </CardTitle>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge variant="outline" className={getTypeColor(channel.type)}>
                    {channel.type}
                  </Badge>
                  <Button variant="ghost" size="sm" className={`
                    h-6 w-6 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    {channel.notifications ? 
                      <Volume2 className="w-3 h-3 text-green-400" /> : 
                      <VolumeX className="w-3 h-3 text-red-400" />
                    }
                  </Button>
                </div>
              </div>
              <CardDescription className={`transition-colors ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                {channel.description}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-4 text-center">
                <div>
                  <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {channel.members}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Members
                  </div>
                </div>
                <div>
                  <div className={`text-lg font-bold text-blue-400`}>
                    {channel.messageCount}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Messages
                  </div>
                </div>
              </div>
              
              <div className="flex items-center justify-between pt-2 border-t border-zinc-700">
                <span className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                  Active {channel.lastActivity}
                </span>
                <div className="flex items-center space-x-1">
                  <Button variant="ghost" size="sm" className={`
                    h-6 w-6 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Eye className="w-3 h-3" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-6 w-6 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Edit className="w-3 h-3" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-6 w-6 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <ExternalLink className="w-3 h-3" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

/**
 * Notification History Component
 */
const NotificationHistory = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [notifications] = useState(MOCK_NOTIFICATIONS);

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'critical': return 'text-red-400 border-red-400 bg-red-500/10';
      case 'warning': return 'text-yellow-400 border-yellow-400 bg-yellow-500/10';
      case 'info': return 'text-blue-400 border-blue-400 bg-blue-500/10';
      default: return 'text-gray-400 border-gray-400 bg-gray-500/10';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'sent': return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'pending': return <Clock className="w-4 h-4 text-yellow-400" />;
      default: return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className={`text-lg font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
          Recent Notifications
        </h3>
        <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white">
          <Send className="w-4 h-4 mr-2" />
          Send Test Message
        </Button>
      </div>
      
      <div className="space-y-3">
        {notifications.map((notification) => (
          <Card key={notification.id} className={`
            transition-all duration-300
            ${isDark 
              ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
              : 'border-gray-200 bg-white/80 backdrop-blur-sm'
            }
          `}>
            <CardContent className="p-4">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h4 className={`font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                      {notification.title}
                    </h4>
                    <Badge variant="outline" className={getPriorityColor(notification.priority)}>
                      {notification.priority}
                    </Badge>
                    <div className="flex items-center space-x-1">
                      {getStatusIcon(notification.status)}
                      <span className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        {notification.status}
                      </span>
                    </div>
                  </div>
                  <p className={`text-sm mb-2 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    {notification.message}
                  </p>
                  <div className="flex items-center space-x-4 text-xs">
                    <div className="flex items-center">
                      <Hash className={`w-3 h-3 mr-1 ${isDark ? 'text-zinc-500' : 'text-gray-500'}`} />
                      <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                        {notification.channel}
                      </span>
                    </div>
                    <div className="flex items-center">
                      <Clock className={`w-3 h-3 mr-1 ${isDark ? 'text-zinc-500' : 'text-gray-500'}`} />
                      <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                        {new Date(notification.timestamp).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-1">
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <Eye className="w-4 h-4" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <RefreshCw className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

/**
 * Main Slack Integration Component
 */
const SlackIntegration = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');

  // Mock analytics data
  const messageActivityData = [
    { hour: '00', messages: 2 },
    { hour: '06', messages: 5 },
    { hour: '09', messages: 15 },
    { hour: '12', messages: 12 },
    { hour: '15', messages: 18 },
    { hour: '18', messages: 8 },
    { hour: '21', messages: 4 }
  ];

  const channelActivityData = [
    { name: 'security-alerts', messages: 247 },
    { name: 'vulnerability-reports', messages: 134 },
    { name: 'incident-response', messages: 56 },
    { name: 'general', messages: 892 }
  ];

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className={`text-2xl font-bold transition-colors ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Slack Integration
          </h2>
          <p className={`transition-colors ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Manage team communication channels and notification settings
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-yellow-400 border-yellow-400">
            <AlertTriangle className="w-3 h-3 mr-1" />
            Warning
          </Badge>
          <Button variant="outline" size="sm" className={`
            ${isDark 
              ? 'border-zinc-700 text-zinc-300 hover:bg-zinc-800' 
              : 'border-gray-300 text-gray-700 hover:bg-gray-50'
            }
          `}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Sync Now
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`grid w-full grid-cols-4 ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}`}>
          <TabsTrigger value="overview" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Overview
          </TabsTrigger>
          <TabsTrigger value="channels" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Channels
          </TabsTrigger>
          <TabsTrigger value="notifications" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Notifications
          </TabsTrigger>
          <TabsTrigger value="config" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Configuration
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Active Channels', value: '15', icon: Hash, color: 'text-blue-400' },
              { title: 'Team Members', value: '28', icon: Users, color: 'text-green-400' },
              { title: 'Daily Messages', value: '1.2K', icon: MessageSquare, color: 'text-purple-400' },
              { title: 'Notifications Sent', value: '234', icon: Bell, color: 'text-orange-400' }
            ].map((stat, index) => (
              <Card key={index} className={`
                transition-all duration-300 hover:scale-105
                ${isDark 
                  ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
                  : 'border-gray-200 bg-white/80 backdrop-blur-sm'
                }
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

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className={`
              ${isDark 
                ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
                : 'border-gray-200 bg-white/80 backdrop-blur-sm'
              }
            `}>
              <CardHeader>
                <CardTitle className={isDark ? 'text-zinc-100' : 'text-gray-900'}>
                  Message Activity (24h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={messageActivityData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                    <XAxis 
                      dataKey="hour" 
                      stroke={isDark ? "#9CA3AF" : "#6B7280"}
                      fontSize={10}
                    />
                    <YAxis stroke={isDark ? "#9CA3AF" : "#6B7280"} fontSize={10} />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#18181b' : '#ffffff', 
                        border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}
                      labelStyle={{ color: isDark ? '#fafafa' : '#1f2937' }}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="messages" 
                      stroke="#10B981" 
                      fill="#10B981"
                      fillOpacity={0.2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className={`
              ${isDark 
                ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
                : 'border-gray-200 bg-white/80 backdrop-blur-sm'
              }
            `}>
              <CardHeader>
                <CardTitle className={isDark ? 'text-zinc-100' : 'text-gray-900'}>
                  Channel Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={channelActivityData} layout="horizontal">
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                    <XAxis 
                      type="number"
                      stroke={isDark ? "#9CA3AF" : "#6B7280"}
                      fontSize={10}
                    />
                    <YAxis 
                      type="category"
                      dataKey="name" 
                      stroke={isDark ? "#9CA3AF" : "#6B7280"}
                      fontSize={10}
                      width={120}
                    />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#18181b' : '#ffffff', 
                        border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}
                      labelStyle={{ color: isDark ? '#fafafa' : '#1f2937' }}
                    />
                    <Bar dataKey="messages" fill="#10B981" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="channels" className="mt-6">
          <ChannelManagement />
        </TabsContent>

        <TabsContent value="notifications" className="mt-6">
          <NotificationHistory />
        </TabsContent>

        <TabsContent value="config" className="mt-6">
          <SlackConfiguration />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SlackIntegration; 