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
  Ticket, 
  Settings, 
  Plus, 
  Eye, 
  Edit, 
  CheckCircle, 
  Clock, 
  AlertTriangle,
  User,
  Calendar,
  Tag,
  ArrowUp,
  ArrowRight,
  ArrowDown,
  RefreshCw,
  ExternalLink,
  Filter,
  Search
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import { useTheme } from '../darkmode/ThemeProvider';

/**
 * Mock JIRA Data
 */
const MOCK_TICKETS = [
  {
    id: 'SEC-101',
    title: 'Critical SQL Injection Vulnerability',
    description: 'SQL injection vulnerability found in user authentication module',
    status: 'In Progress',
    priority: 'Critical',
    assignee: 'John Doe',
    reporter: 'AI Guardian',
    created: '2024-01-15T10:30:00Z',
    updated: '2024-01-16T14:20:00Z',
    project: 'Security',
    labels: ['security', 'critical', 'sql-injection'],
    components: ['Authentication', 'Database']
  },
  {
    id: 'SEC-102',
    title: 'XSS Vulnerability in Dashboard',
    description: 'Cross-site scripting vulnerability in the admin dashboard',
    status: 'To Do',
    priority: 'High',
    assignee: 'Jane Smith',
    reporter: 'AI Guardian',
    created: '2024-01-16T09:15:00Z',
    updated: '2024-01-16T09:15:00Z',
    project: 'Security',
    labels: ['security', 'xss', 'frontend'],
    components: ['Dashboard', 'Frontend']
  },
  {
    id: 'SEC-103',
    title: 'Outdated Dependencies',
    description: 'Multiple outdated npm packages with known vulnerabilities',
    status: 'Done',
    priority: 'Medium',
    assignee: 'Bob Wilson',
    reporter: 'AI Guardian',
    created: '2024-01-14T16:45:00Z',
    updated: '2024-01-16T11:30:00Z',
    project: 'Security',
    labels: ['dependencies', 'npm', 'maintenance'],
    components: ['Build System']
  }
];

const MOCK_PROJECTS = [
  {
    key: 'SEC',
    name: 'Security',
    description: 'Security-related tickets and vulnerabilities',
    lead: 'John Doe',
    issueCount: 45,
    activeIssues: 12,
    resolvedIssues: 33
  },
  {
    key: 'PERF',
    name: 'Performance',
    description: 'Performance optimization and monitoring',
    lead: 'Jane Smith',
    issueCount: 23,
    activeIssues: 8,
    resolvedIssues: 15
  },
  {
    key: 'FEAT',
    name: 'Features',
    description: 'New feature development and enhancements',
    lead: 'Bob Wilson',
    issueCount: 67,
    activeIssues: 25,
    resolvedIssues: 42
  }
];

/**
 * JIRA Configuration Component
 */
const JiraConfiguration = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [config, setConfig] = useState({
    serverUrl: 'https://aiGuardian.atlassian.net',
    username: 'admin@aiGuardian.com',
    apiToken: '••••••••••••••••••••••••••••••••',
    defaultProject: 'SEC',
    autoCreateTickets: true,
    autoAssignTickets: false,
    syncInterval: 15,
    webhookUrl: 'https://api.aiGuardian.com/webhooks/jira'
  });

  const handleSave = () => {
    console.log('Saving JIRA configuration:', config);
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
          JIRA Configuration
        </CardTitle>
        <CardDescription className={`
          transition-colors
          ${isDark ? 'text-zinc-400' : 'text-gray-600'}
        `}>
          Configure your JIRA server connection and automation settings
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Server URL
              </Label>
              <Input
                value={config.serverUrl}
                onChange={(e) => setConfig({...config, serverUrl: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Username/Email
              </Label>
              <Input
                value={config.username}
                onChange={(e) => setConfig({...config, username: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                API Token
              </Label>
              <Input
                type="password"
                value={config.apiToken}
                onChange={(e) => setConfig({...config, apiToken: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Default Project
              </Label>
              <Select value={config.defaultProject} onValueChange={(value) => setConfig({...config, defaultProject: value})}>
                <SelectTrigger className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="SEC">Security (SEC)</SelectItem>
                  <SelectItem value="PERF">Performance (PERF)</SelectItem>
                  <SelectItem value="FEAT">Features (FEAT)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div className="space-y-4">
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Sync Interval (minutes)
              </Label>
              <Input
                type="number"
                value={config.syncInterval}
                onChange={(e) => setConfig({...config, syncInterval: parseInt(e.target.value)})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div>
              <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                Webhook URL
              </Label>
              <Input
                value={config.webhookUrl}
                onChange={(e) => setConfig({...config, webhookUrl: e.target.value})}
                className={`mt-1 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
              />
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                  Auto-create tickets for vulnerabilities
                </Label>
                <Switch
                  checked={config.autoCreateTickets}
                  onCheckedChange={(checked) => setConfig({...config, autoCreateTickets: checked})}
                />
              </div>
              
              <div className="flex items-center justify-between">
                <Label className={`text-sm font-medium ${isDark ? 'text-zinc-200' : 'text-gray-700'}`}>
                  Auto-assign tickets
                </Label>
                <Switch
                  checked={config.autoAssignTickets}
                  onCheckedChange={(checked) => setConfig({...config, autoAssignTickets: checked})}
                />
              </div>
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
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Ticket Management Component
 */
const TicketManagement = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [tickets, setTickets] = useState(MOCK_TICKETS);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const getPriorityIcon = (priority) => {
    switch (priority.toLowerCase()) {
      case 'critical': return <ArrowUp className="w-4 h-4 text-red-500" />;
      case 'high': return <ArrowUp className="w-4 h-4 text-orange-500" />;
      case 'medium': return <ArrowRight className="w-4 h-4 text-yellow-500" />;
      case 'low': return <ArrowDown className="w-4 h-4 text-green-500" />;
      default: return <ArrowRight className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'done': return 'text-green-400 border-green-400 bg-green-500/10';
      case 'in progress': return 'text-blue-400 border-blue-400 bg-blue-500/10';
      case 'to do': return 'text-yellow-400 border-yellow-400 bg-yellow-500/10';
      default: return 'text-gray-400 border-gray-400 bg-gray-500/10';
    }
  };

  const filteredTickets = tickets.filter(ticket => {
    const matchesFilter = filter === 'all' || ticket.status.toLowerCase().replace(' ', '-') === filter;
    const matchesSearch = ticket.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         ticket.id.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-4">
      {/* Header and Controls */}
      <div className="flex items-center justify-between">
        <h3 className={`text-lg font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
          JIRA Tickets
        </h3>
        <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white">
          <Plus className="w-4 h-4 mr-2" />
          Create Ticket
        </Button>
      </div>
      
      {/* Filters */}
      <div className="flex items-center space-x-4">
        <div className="flex-1">
          <div className="relative">
            <Search className={`absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 ${isDark ? 'text-zinc-400' : 'text-gray-400'}`} />
            <Input
              placeholder="Search tickets..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className={`pl-10 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}
            />
          </div>
        </div>
        
        <Select value={filter} onValueChange={setFilter}>
          <SelectTrigger className={`w-40 ${isDark ? 'bg-zinc-800 border-zinc-700' : 'bg-white border-gray-300'}`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tickets</SelectItem>
            <SelectItem value="to-do">To Do</SelectItem>
            <SelectItem value="in-progress">In Progress</SelectItem>
            <SelectItem value="done">Done</SelectItem>
          </SelectContent>
        </Select>
        
        <Button variant="outline" size="sm" className={`
          ${isDark 
            ? 'border-zinc-700 text-zinc-300 hover:bg-zinc-800' 
            : 'border-gray-300 text-gray-700 hover:bg-gray-50'
          }
        `}>
          <Filter className="w-4 h-4 mr-2" />
          Filter
        </Button>
      </div>
      
      {/* Tickets List */}
      <div className="space-y-3">
        {filteredTickets.map((ticket) => (
          <Card key={ticket.id} className={`
            transition-all duration-300 hover:scale-[1.02]
            ${isDark 
              ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
              : 'border-gray-200 bg-white/80 backdrop-blur-sm'
            }
          `}>
            <CardContent className="p-4">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <Badge variant="outline" className="font-mono text-xs px-2 py-1">
                      {ticket.id}
                    </Badge>
                    <Badge variant="outline" className={getStatusColor(ticket.status)}>
                      {ticket.status}
                    </Badge>
                    <div className="flex items-center">
                      {getPriorityIcon(ticket.priority)}
                      <span className={`ml-1 text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                        {ticket.priority}
                      </span>
                    </div>
                  </div>
                  
                  <h4 className={`font-semibold mb-1 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {ticket.title}
                  </h4>
                  
                  <p className={`text-sm mb-3 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    {ticket.description}
                  </p>
                  
                  <div className="flex items-center space-x-4 text-xs">
                    <div className="flex items-center">
                      <User className={`w-3 h-3 mr-1 ${isDark ? 'text-zinc-500' : 'text-gray-500'}`} />
                      <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                        {ticket.assignee}
                      </span>
                    </div>
                    <div className="flex items-center">
                      <Calendar className={`w-3 h-3 mr-1 ${isDark ? 'text-zinc-500' : 'text-gray-500'}`} />
                      <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                        {new Date(ticket.updated).toLocaleDateString()}
                      </span>
                    </div>
                    <div className="flex items-center">
                      <Tag className={`w-3 h-3 mr-1 ${isDark ? 'text-zinc-500' : 'text-gray-500'}`} />
                      <span className={isDark ? 'text-zinc-500' : 'text-gray-500'}>
                        {ticket.project}
                      </span>
                    </div>
                  </div>
                  
                  {/* Labels */}
                  <div className="flex flex-wrap gap-1 mt-2">
                    {ticket.labels.map((label, index) => (
                      <Badge key={index} variant="secondary" className="text-xs px-2 py-0">
                        {label}
                      </Badge>
                    ))}
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
                    <Edit className="w-4 h-4" />
                  </Button>
                  <Button variant="ghost" size="sm" className={`
                    h-8 w-8 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                  `}>
                    <ExternalLink className="w-4 h-4" />
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
 * Project Management Component
 */
const ProjectManagement = () => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [projects] = useState(MOCK_PROJECTS);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className={`text-lg font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
          JIRA Projects
        </h3>
        <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white">
          <Plus className="w-4 h-4 mr-2" />
          Create Project
        </Button>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
        {projects.map((project) => (
          <Card key={project.key} className={`
            transition-all duration-300 hover:scale-105
            ${isDark 
              ? 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm' 
              : 'border-gray-200 bg-white/80 backdrop-blur-sm'
            }
          `}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <Badge variant="outline" className="font-mono text-xs px-2 py-1">
                  {project.key}
                </Badge>
                <Button variant="ghost" size="sm" className={`
                  h-6 w-6 p-0 ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                `}>
                  <ExternalLink className="w-3 h-3" />
                </Button>
              </div>
              <CardTitle className={`text-base font-semibold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                {project.name}
              </CardTitle>
              <CardDescription className={`transition-colors ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                {project.description}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-3 gap-4 text-center">
                <div>
                  <div className={`text-lg font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                    {project.issueCount}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Total Issues
                  </div>
                </div>
                <div>
                  <div className={`text-lg font-bold text-blue-400`}>
                    {project.activeIssues}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Active
                  </div>
                </div>
                <div>
                  <div className={`text-lg font-bold text-green-400`}>
                    {project.resolvedIssues}
                  </div>
                  <div className={`text-xs ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                    Resolved
                  </div>
                </div>
              </div>
              
              <div className="flex items-center justify-between pt-2 border-t border-zinc-700">
                <div className="flex items-center">
                  <User className={`w-3 h-3 mr-1 ${isDark ? 'text-zinc-500' : 'text-gray-500'}`} />
                  <span className={`text-xs ${isDark ? 'text-zinc-500' : 'text-gray-500'}`}>
                    Lead: {project.lead}
                  </span>
                </div>
                <Button variant="ghost" size="sm" className={`
                  text-xs ${isDark ? 'hover:bg-zinc-800' : 'hover:bg-gray-100'}
                `}>
                  View Details
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

/**
 * Main JIRA Integration Component
 */
const JiraIntegration = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('overview');

  // Mock analytics data
  const ticketStatusData = [
    { name: 'To Do', value: 12, color: '#FbbF24' },
    { name: 'In Progress', value: 18, color: '#3B82F6' },
    { name: 'Done', value: 33, color: '#10B981' },
    { name: 'Won\'t Do', value: 4, color: '#6B7280' }
  ];

  const weeklyActivityData = [
    { day: 'Mon', created: 3, resolved: 2 },
    { day: 'Tue', created: 5, resolved: 4 },
    { day: 'Wed', created: 2, resolved: 6 },
    { day: 'Thu', created: 4, resolved: 3 },
    { day: 'Fri', created: 6, resolved: 5 },
    { day: 'Sat', created: 1, resolved: 1 },
    { day: 'Sun', created: 0, resolved: 2 }
  ];

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className={`text-2xl font-bold transition-colors ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            JIRA Integration
          </h2>
          <p className={`transition-colors ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Manage tickets, projects, and track development progress
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="text-green-400 border-green-400">
            <CheckCircle className="w-3 h-3 mr-1" />
            Connected
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
          <TabsTrigger value="tickets" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Tickets
          </TabsTrigger>
          <TabsTrigger value="projects" className={`
            ${isDark 
              ? 'data-[state=active]:bg-zinc-700 data-[state=active]:text-zinc-100 text-zinc-400' 
              : 'data-[state=active]:bg-white data-[state=active]:text-gray-900 text-gray-600'
            }
          `}>
            Projects
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
              { title: 'Total Tickets', value: '67', icon: Ticket, color: 'text-blue-400' },
              { title: 'Open Tickets', value: '30', icon: Clock, color: 'text-yellow-400' },
              { title: 'Resolved Today', value: '8', icon: CheckCircle, color: 'text-green-400' },
              { title: 'Critical Issues', value: '3', icon: AlertTriangle, color: 'text-red-400' }
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
                  Ticket Status Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={ticketStatusData}
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {ticketStatusData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#18181b' : '#ffffff', 
                        border: `1px solid ${isDark ? '#3f3f46' : '#e5e7eb'}`,
                        borderRadius: '8px'
                      }}
                      labelStyle={{ color: isDark ? '#fafafa' : '#1f2937' }}
                    />
                  </PieChart>
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
                  Weekly Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={weeklyActivityData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#374151" : "#E5E7EB"} />
                    <XAxis 
                      dataKey="day" 
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
                    <Bar dataKey="created" fill="#3B82F6" name="Created" />
                    <Bar dataKey="resolved" fill="#10B981" name="Resolved" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="tickets" className="mt-6">
          <TicketManagement />
        </TabsContent>

        <TabsContent value="projects" className="mt-6">
          <ProjectManagement />
        </TabsContent>

        <TabsContent value="config" className="mt-6">
          <JiraConfiguration />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default JiraIntegration; 