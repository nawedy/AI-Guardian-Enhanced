import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FileText, Download, TrendingUp, Users } from 'lucide-react';
import { useTheme } from '../darkmode/ThemeProvider';

const AdvancedReporting = ({ className = '' }) => {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <div className={`space-y-6 p-6 min-h-screen ${isDark ? 'bg-zinc-950' : 'bg-gray-50'} ${className}`}>
      <div className="flex items-center justify-between">
        <div>
          <h1 className={`text-3xl font-bold ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            Advanced Reporting & Analytics
          </h1>
          <p className={`mt-1 ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Executive dashboards, PDF exports, and automated compliance reporting
          </p>
        </div>
        <Button variant="outline" size="sm">
          <Download className="h-4 w-4 mr-2" />
          Export Report
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { title: 'Total Reports', value: '1,247', icon: FileText, color: 'text-blue-400' },
          { title: 'Executive Reports', value: '34', icon: Users, color: 'text-purple-400' },
          { title: 'PDF Exports', value: '567', icon: Download, color: 'text-orange-400' },
          { title: 'Compliance Score', value: '94.2%', icon: TrendingUp, color: 'text-green-400' }
        ].map((stat, index) => (
          <Card key={index} className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
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

      <Card className={`${isDark ? 'border-zinc-800 bg-zinc-900/50' : 'border-gray-200 bg-white/80'}`}>
        <CardHeader>
          <CardTitle className={`flex items-center ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
            <FileText className="w-5 h-5 mr-2 text-blue-400" />
            Advanced Reporting Features
          </CardTitle>
          <CardDescription className={`${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
            Comprehensive reporting and analytics capabilities
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              'Executive Security Summary',
              'Compliance Status Report', 
              'Vulnerability Assessment',
              'Risk Analysis Dashboard',
              'Incident Response Summary',
              'Privacy Impact Assessment'
            ].map((feature, index) => (
              <div key={index} className={`p-4 rounded-lg border ${isDark ? 'border-zinc-700 bg-zinc-800/30' : 'border-gray-200 bg-gray-50'}`}>
                <h4 className={`font-semibold mb-2 ${isDark ? 'text-zinc-100' : 'text-gray-900'}`}>
                  {feature}
                </h4>
                <p className={`text-sm ${isDark ? 'text-zinc-400' : 'text-gray-600'}`}>
                  Automated report generation with PDF export capabilities
                </p>
                <Button variant="outline" size="sm" className="mt-3">
                  Generate Report
                </Button>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AdvancedReporting;
