"use client"

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  BarChart3, 
  MessageSquare, 
  Ticket, 
  Settings, 
  CheckCircle, 
  AlertTriangle, 
  Clock,
  Activity,
  Link,
  RefreshCw,
  Plus,
  ExternalLink,
  Zap,
  Bell,
  Database
} from 'lucide-react';
import { useTheme } from '../darkmode/ThemeProvider';
import GrafanaIntegration from './GrafanaIntegration';
import JiraIntegration from './JiraIntegration';
import SlackIntegration from './SlackIntegration';

/**
 * Integration Status Configuration
 */
const INTEGRATION_STATUS = {
  connected: { 
    color: 'bg-green-500', 
    text: 'Connected', 
    textColor: 'text-green-400',
    icon: CheckCircle 
  },
  warning: { 
    color: 'bg-yellow-500', 
    text: 'Warning', 
    textColor: 'text-yellow-400',
    icon: AlertTriangle 
  },
  disconnected: { 
    color: 'bg-red-500', 
    text: 'Disconnected', 
    textColor: 'text-red-400',
    icon: AlertTriangle 
  },
  configuring: { 
    color: 'bg-blue-500', 
    text: 'Configuring', 
    textColor: 'text-blue-400',
    icon: Clock 
  },
};

/**
 * Integration Overview Card Component
 */
const IntegrationOverviewCard = ({ integration, status, metrics, onConfigure }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const statusConfig = INTEGRATION_STATUS[status] || INTEGRATION_STATUS.disconnected;
  const StatusIcon = statusConfig.icon;

  return (
    <Card className={`
      transition-all duration-300 hover:scale-105 hover:shadow-lg cursor-pointer
      ${isDark 
        ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm shadow-zinc-900/20' 
        : 'border-gray-200 bg-white/80 backdrop-blur-sm shadow-gray-200/50'
      }
    `}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
        <div className="flex items-center space-x-3">
          <div className={`p-3 rounded-lg ${integration.color}`}>
            <integration.icon className="h-6 w-6 text-white" />
          </div>
          <div>
            <CardTitle className={`
              text-lg font-semibold transition-colors
              ${isDark ? 'text-zinc-100' : 'text-gray-900'}
            `}>
              {integration.name}
            </CardTitle>
            <CardDescription className={`
              transition-colors
              ${isDark ? 'text-zinc-400' : 'text-gray-600'}
            `}>
              {integration.description}
            </CardDescription>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <div className={`w-3 h-3 rounded-full ${statusConfig.color} animate-pulse`}></div>
          <Badge variant="outline" className={`
            ${statusConfig.textColor} transition-colors
            ${isDark ? 'border-zinc-600' : 'border-gray-300'}
          `}>
            <StatusIcon className="w-3 h-3 mr-1" />
            {statusConfig.text}
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Metrics */}
        <div className="grid grid-cols-2 gap-4">
          {Object.entries(metrics).map(([key, value]) => (
            <div key={key} className="text-center">
              <div className={`
                text-2xl font-bold transition-colors
                ${isDark ? 'text-zinc-100' : 'text-gray-900'}
              `}>
                {value}
              </div>
              <div className={`
                text-xs capitalize transition-colors
                ${isDark ? 'text-zinc-400' : 'text-gray-600'}
              `}>
                {key.replace(/([A-Z])/g, ' $1').toLowerCase()}
              </div>
            </div>
          ))}
        </div>
        
        {/* Action Button */}
        <Button 
          onClick={() => onConfigure(integration.key)}
          className={`
            w-full transition-colors
            ${status === 'connected' 
              ? isDark 
                ? 'bg-zinc-800 hover:bg-zinc-700 text-zinc-100' 
                : 'bg-gray-100 hover:bg-gray-200 text-gray-900'
              : 'bg-blue-600 hover:bg-blue-700 text-white'
            }
          `}
        >
          {status === 'connected' ? (
            <>
              <Settings className="w-4 h-4 mr-2" />
              Manage
            </>
          ) : (
            <>
              <Plus className="w-4 h-4 mr-2" />
              Configure
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
};

/**
 * Quick Actions Component
 */
const QuickActions = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const actions = [
    {
      title: 'Sync All Integrations',
      description: 'Refresh data from all connected services',
      icon: RefreshCw,
      action: () => console.log('Syncing all integrations'),
      color: 'bg-blue-600'
    },
    {
      title: 'Test Notifications',
      description: 'Send test notifications to all channels',
      icon: Bell,
      action: () => console.log('Testing notifications'),
      color: 'bg-green-600'
    },
    {
      title: 'Export Integration Report',
      description: 'Generate integration status report',
      icon: Database,
      action: () => console.log('Exporting report'),
      color: 'bg-purple-600'
    },
  ];

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
          <Zap className="w-5 h-5 mr-2" />
          Quick Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {actions.map((action, index) => (
          <Button
            key={index}
            variant="outline"
            onClick={action.action}
            className={`
              w-full justify-start h-auto p-4 transition-all duration-200
              ${isDark 
                ? 'border-zinc-700 hover:bg-zinc-800 text-zinc-100' 
                : 'border-gray-300 hover:bg-gray-50 text-gray-900'
              }
            `}
          >
            <div className={`p-2 rounded-lg mr-3 ${action.color}`}>
              <action.icon className="w-4 h-4 text-white" />
            </div>
            <div className="text-left">
              <div className="font-medium">{action.title}</div>
              <div className={`
                text-xs transition-colors
                ${isDark ? 'text-zinc-400' : 'text-gray-600'}
              `}>
                {action.description}
              </div>
            </div>
          </Button>
        ))}
      </CardContent>
    </Card>
  );
};

/**
 * Main Integrations Manager Component
 */
const IntegrationsManager = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');
  const [integrations, setIntegrations] = useState({
    grafana: {
      key: 'grafana',
      name: 'Grafana',
      icon: BarChart3,
      description: 'Monitoring & Analytics Dashboards',
      color: 'bg-orange-600',
      status: 'connected',
      metrics: {
        dashboards: 12,
        alerts: 3,
        dataPoints: '2.4M',
        uptime: '99.8%'
      }
    },
    jira: {
      key: 'jira',
      name: 'Jira',
      icon: Ticket,
      description: 'Issue Tracking & Project Management',
      color: 'bg-blue-600',
      status: 'connected',
      metrics: {
        tickets: 45,
        open: 12,
        resolved: 33,
        projects: 8
      }
    },
    slack: {
      key: 'slack',
      name: 'Slack',
      icon: MessageSquare,
      description: 'Team Communication & Notifications',
      color: 'bg-green-600',
      status: 'warning',
      metrics: {
        channels: 15,
        messages: '1.2K',
        notifications: 234,
        users: 28
      }
    }
  });

  const handleConfigure = (integrationKey) => {
    setActiveTab(integrationKey);
  };

  // Calculate overview stats
  const overviewStats = {
    totalIntegrations: Object.keys(integrations).length,
    connectedIntegrations: Object.values(integrations).filter(i => i.status === 'connected').length,
    totalAlerts: Object.values(integrations).reduce((sum, i) => sum + (i.metrics.alerts || 0), 0),
    systemHealth: Math.round(
      (Object.values(integrations).filter(i => i.status === 'connected').length / Object.keys(integrations).length) * 100
    )
  };

  return (
    <div className={`
      space-y-6 p-6 min-h-screen transition-colors duration-300
      ${isDark ? 'bg-zinc-950' : 'bg-gray-50'}
      ${className}
    `}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`
            text-3xl font-bold transition-colors
            ${isDark ? 'text-zinc-100' : 'text-gray-900'}
          `}>
            Enterprise Integrations
          </h1>
          <p className={`
            mt-1 transition-colors
            ${isDark ? 'text-zinc-400' : 'text-gray-600'}
          `}>
            Manage your enterprise tool integrations and workflows
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Badge 
            variant="outline" 
            className={`
              transition-colors
              ${overviewStats.systemHealth > 80 
                ? 'text-green-400 border-green-400' 
                : 'text-yellow-400 border-yellow-400'
              }
            `}
          >
            System Health: {overviewStats.systemHealth}%
          </Badge>
          <Button 
            variant="outline" 
            size="sm"
            className={`
              transition-colors
              ${isDark 
                ? 'border-zinc-700 bg-zinc-800 text-zinc-100 hover:bg-zinc-700' 
                : 'border-gray-300 bg-white text-gray-900 hover:bg-gray-50'
              }
            `}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh All
          </Button>
        </div>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className={`
          grid w-full grid-cols-4 transition-colors
          ${isDark ? 'bg-zinc-800' : 'bg-gray-100'}
        `}>
          <TabsTrigger 
            value="overview"
            className={`
              transition-colors
              ${isDark 
                ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
                : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
              }
            `}
          >
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger 
            value="grafana"
            className={`
              transition-colors
              ${isDark 
                ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
                : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
              }
            `}
          >
            <BarChart3 className="w-4 h-4 mr-2" />
            Grafana
          </TabsTrigger>
          <TabsTrigger 
            value="jira"
            className={`
              transition-colors
              ${isDark 
                ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
                : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
              }
            `}
          >
            <Ticket className="w-4 h-4 mr-2" />
            Jira
          </TabsTrigger>
          <TabsTrigger 
            value="slack"
            className={`
              transition-colors
              ${isDark 
                ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
                : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
              }
            `}
          >
            <MessageSquare className="w-4 h-4 mr-2" />
            Slack
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { title: 'Total Integrations', value: overviewStats.totalIntegrations, icon: Link, color: 'text-blue-400' },
              { title: 'Connected', value: overviewStats.connectedIntegrations, icon: CheckCircle, color: 'text-green-400' },
              { title: 'Active Alerts', value: overviewStats.totalAlerts, icon: AlertTriangle, color: 'text-yellow-400' },
              { title: 'System Health', value: `${overviewStats.systemHealth}%`, icon: Activity, color: 'text-purple-400' }
            ].map((stat, index) => (
              <Card key={index} className={`
                transition-all duration-300 hover:scale-105
                ${isDark 
                  ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
                  : 'border-gray-200 bg-white/80 backdrop-blur-sm'
                }
              `}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className={`
                    text-sm font-medium transition-colors
                    ${isDark ? 'text-zinc-100' : 'text-gray-900'}
                  `}>
                    {stat.title}
                  </CardTitle>
                  <stat.icon className={`h-4 w-4 ${stat.color}`} />
                </CardHeader>
                <CardContent>
                  <div className={`
                    text-2xl font-bold transition-colors
                    ${isDark ? 'text-zinc-50' : 'text-gray-900'}
                  `}>
                    {stat.value}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Integration Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {Object.values(integrations).map((integration) => (
              <IntegrationOverviewCard
                key={integration.key}
                integration={integration}
                status={integration.status}
                metrics={integration.metrics}
                onConfigure={handleConfigure}
              />
            ))}
          </div>

          {/* Quick Actions */}
          <QuickActions />
        </TabsContent>

        {/* Integration-specific tabs */}
        <TabsContent value="grafana" className="mt-6">
          <GrafanaIntegration />
        </TabsContent>

        <TabsContent value="jira" className="mt-6">
          <JiraIntegration />
        </TabsContent>

        <TabsContent value="slack" className="mt-6">
          <SlackIntegration />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default IntegrationsManager; 