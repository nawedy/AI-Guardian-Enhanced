"use client"

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  TrendingUp, 
  Activity, 
  Shield, 
  AlertTriangle, 
  CheckCircle,
  RefreshCw,
  Download,
  Users,
  Globe
} from 'lucide-react';
import ServiceMetrics from './ServiceMetrics';
import KPIEngine from './KPIEngine';

const AnalyticsDashboard = ({ className = '' }) => {
  const [timeRange, setTimeRange] = useState('24h');
  const [activeTab, setActiveTab] = useState('overview');

  const overview = {
    totalServices: 8,
    healthyServices: 7,
    totalScans: 125643,
    criticalVulnerabilities: 23,
    activeUsers: 45,
    systemUptime: 99.7,
  };

  const cards = [
    {
      title: 'Total Services',
      value: overview.totalServices,
      icon: Activity,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
    },
    {
      title: 'Healthy Services', 
      value: overview.healthyServices,
      icon: CheckCircle,  
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
    },
    {
      title: 'Total Scans',
      value: overview.totalScans.toLocaleString(),
      icon: Shield,
      color: 'text-purple-400', 
      bgColor: 'bg-purple-500/10',
    },
    {
      title: 'Critical Issues',
      value: overview.criticalVulnerabilities,
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
    },
    {
      title: 'Active Users',
      value: overview.activeUsers,
      icon: Users,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
    },
    {
      title: 'System Uptime',
      value: `${overview.systemUptime}%`,
      icon: Globe,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
    },
  ];

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Dashboard Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-zinc-100">Analytics Dashboard</h1>
          <p className="text-zinc-400 mt-1">Real-time security analytics and monitoring</p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-40 bg-zinc-800 border-zinc-700">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-zinc-800 border-zinc-700">
              <SelectItem value="1h" className="text-zinc-100">Last Hour</SelectItem>
              <SelectItem value="24h" className="text-zinc-100">Last 24 Hours</SelectItem>
              <SelectItem value="7d" className="text-zinc-100">Last 7 Days</SelectItem>
              <SelectItem value="30d" className="text-zinc-100">Last 30 Days</SelectItem>
            </SelectContent>
          </Select>
          
          <Button variant="outline" size="sm" className="border-zinc-700">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          
          <Button variant="outline" size="sm" className="border-zinc-700">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Dashboard Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3 bg-zinc-800">
          <TabsTrigger value="overview">System Overview</TabsTrigger>
          <TabsTrigger value="services">Service Metrics</TabsTrigger>
          <TabsTrigger value="security">Security Analytics</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* System Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
            {cards.map((card, index) => (
              <Card key={index} className="border-zinc-800 bg-zinc-900/50 backdrop-blur-sm">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-zinc-100">
                    {card.title}
                  </CardTitle>
                  <div className={`p-2 rounded-lg ${card.bgColor}`}>
                    <card.icon className={`h-4 w-4 ${card.color}`} />
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-zinc-50 mb-1">
                    {card.value}
                  </div>
                  <div className="flex items-center text-xs text-zinc-400">
                    <TrendingUp className="h-3 w-3 mr-1 text-green-400" />
                    <span className="text-green-400">+5.1%</span>
                    <span className="ml-1">vs last period</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="services" className="mt-6">
          <ServiceMetrics />
        </TabsContent>

        <TabsContent value="security" className="space-y-6 mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <KPIEngine serviceType="code-scanner" />
            <KPIEngine serviceType="api-gateway" />
          </div>
        </TabsContent>
      </Tabs>

      {/* Dashboard Footer */}
      <div className="flex items-center justify-between text-sm text-zinc-400 border-t border-zinc-800 pt-4">
        <div className="flex items-center space-x-4">
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
          <Badge variant="outline" className="text-green-400 border-green-400">
            System Healthy
          </Badge>
        </div>
      </div>
    </div>
  );
};

export default AnalyticsDashboard; 