// src/components/analytics/KPIEngine.jsx
// Core KPI calculation engine for AI Guardian v4.2.0 enterprise analytics
"use client"

import { useState, useEffect, useCallback, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Activity, TrendingUp, TrendingDown, Minus, AlertTriangle, CheckCircle } from 'lucide-react';

/**
 * API Gateway KPIs Interface
 */
const APIGatewayKPIs = {
  throughput: {
    requestsPerSecond: 0,
    requestsPerMinute: 0,
    requestsPerHour: 0,
    peakThroughput: 0,
  },
  performance: {
    responseTimeP50: 0,
    responseTimeP95: 0,
    responseTimeP99: 0,
    averageResponseTime: 0,
  },
  reliability: {
    errorRate4xx: 0,
    errorRate5xx: 0,
    uptime: 0,
    availability: 0,
  },
  security: {
    authenticationSuccessRate: 0,
    authenticationFailureRate: 0,
    rateLimitingHits: 0,
    suspiciousActivityCount: 0,
  },
};

/**
 * Code Scanner KPIs Interface
 */
const CodeScannerKPIs = {
  scanning: {
    filesScannedPerHour: 0,
    totalLinesScanned: 0,
    scanDurationAverage: 0,
    scanThroughput: 0,
  },
  vulnerabilities: {
    criticalVulnerabilities: 0,
    highVulnerabilities: 0,
    mediumVulnerabilities: 0,
    lowVulnerabilities: 0,
    vulnerabilityTrends: [],
  },
  languages: {
    languageDistribution: [],
    languageSpecificVulnerabilities: [],
    scanningAccuracy: [],
  },
};

/**
 * KPI Calculation Utilities
 */
const KPIUtils = {
  calculatePercentile: (values, percentile) => {
    if (!values.length) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  },

  calculateTrend: (current, previous) => {
    if (!previous || previous === 0) return 0;
    return ((current - previous) / previous) * 100;
  },

  getHealthStatus: (value, thresholds) => {
    if (value >= thresholds.excellent) return { status: 'excellent', color: 'bg-green-500', icon: CheckCircle };
    if (value >= thresholds.good) return { status: 'good', color: 'bg-blue-500', icon: TrendingUp };
    if (value >= thresholds.warning) return { status: 'warning', color: 'bg-yellow-500', icon: Minus };
    return { status: 'critical', color: 'bg-red-500', icon: AlertTriangle };
  },

  formatMetric: (value, type) => {
    switch (type) {
      case 'percentage':
        return `${value.toFixed(1)}%`;
      case 'milliseconds':
        return `${value.toFixed(0)}ms`;
      case 'number':
        return value.toLocaleString();
      case 'throughput':
        return `${value.toFixed(1)}/s`;
      default:
        return value.toString();
    }
  },
};

/**
 * Real-time KPI Data Hook
 */
const useKPIData = (serviceType) => {
  const [kpiData, setKPIData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const fetchKPIData = useCallback(async () => {
    try {
      setLoading(true);
      // TODO: Replace with actual API calls to microservices
      const mockData = await simulateKPIData(serviceType);
      setKPIData(mockData);
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [serviceType]);

  useEffect(() => {
    fetchKPIData();
    const interval = setInterval(fetchKPIData, 5000); // Update every 5 seconds
    return () => clearInterval(interval);
  }, [fetchKPIData]);

  return { kpiData, loading, error, lastUpdated, refetch: fetchKPIData };
};

/**
 * Simulate KPI Data (Replace with actual API integration)
 */
const simulateKPIData = async (serviceType) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      switch (serviceType) {
        case 'api-gateway':
          resolve({
            ...APIGatewayKPIs,
            throughput: {
              requestsPerSecond: Math.random() * 100 + 50,
              requestsPerMinute: Math.random() * 6000 + 3000,
              requestsPerHour: Math.random() * 360000 + 180000,
              peakThroughput: Math.random() * 200 + 150,
            },
            performance: {
              responseTimeP50: Math.random() * 100 + 50,
              responseTimeP95: Math.random() * 300 + 200,
              responseTimeP99: Math.random() * 500 + 400,
              averageResponseTime: Math.random() * 150 + 75,
            },
            reliability: {
              errorRate4xx: Math.random() * 5,
              errorRate5xx: Math.random() * 2,
              uptime: 99.5 + Math.random() * 0.5,
              availability: 99.0 + Math.random() * 1.0,
            },
            security: {
              authenticationSuccessRate: 95 + Math.random() * 5,
              authenticationFailureRate: Math.random() * 5,
              rateLimitingHits: Math.floor(Math.random() * 100),
              suspiciousActivityCount: Math.floor(Math.random() * 10),
            },
          });
        case 'code-scanner':
          resolve({
            ...CodeScannerKPIs,
            scanning: {
              filesScannedPerHour: Math.floor(Math.random() * 1000 + 500),
              totalLinesScanned: Math.floor(Math.random() * 50000 + 25000),
              scanDurationAverage: Math.random() * 5000 + 2000,
              scanThroughput: Math.random() * 100 + 50,
            },
            vulnerabilities: {
              criticalVulnerabilities: Math.floor(Math.random() * 20),
              highVulnerabilities: Math.floor(Math.random() * 100 + 50),
              mediumVulnerabilities: Math.floor(Math.random() * 300 + 200),
              lowVulnerabilities: Math.floor(Math.random() * 500 + 300),
              vulnerabilityTrends: Array.from({ length: 30 }, (_, i) => ({
                date: new Date(Date.now() - (29 - i) * 24 * 60 * 60 * 1000),
                critical: Math.floor(Math.random() * 25),
                high: Math.floor(Math.random() * 120),
                medium: Math.floor(Math.random() * 350),
                low: Math.floor(Math.random() * 600),
              })),
            },
            languages: {
              languageDistribution: [
                { language: 'JavaScript', percentage: 30, files: 1200 },
                { language: 'Python', percentage: 25, files: 1000 },
                { language: 'Java', percentage: 20, files: 800 },
                { language: 'TypeScript', percentage: 15, files: 600 },
                { language: 'Go', percentage: 10, files: 400 },
              ],
              languageSpecificVulnerabilities: [
                { language: 'JavaScript', vulnerabilities: 150, severity: 'high' },
                { language: 'Python', vulnerabilities: 120, severity: 'medium' },
                { language: 'Java', vulnerabilities: 180, severity: 'high' },
                { language: 'TypeScript', vulnerabilities: 90, severity: 'low' },
                { language: 'Go', vulnerabilities: 60, severity: 'low' },
              ],
              scanningAccuracy: [
                { language: 'JavaScript', accuracy: 95.2 },
                { language: 'Python', accuracy: 97.8 },
                { language: 'Java', accuracy: 94.5 },
                { language: 'TypeScript', accuracy: 96.1 },
                { language: 'Go', accuracy: 98.3 },
              ],
            },
          });
        default:
          resolve({});
      }
    }, 300);
  });
};

/**
 * KPI Metric Card Component
 */
const KPIMetricCard = ({ title, value, type, trend, status, description, icon: Icon }) => {
  const healthStatus = KPIUtils.getHealthStatus(value, {
    excellent: type === 'percentage' ? 95 : 100,
    good: type === 'percentage' ? 85 : 80,
    warning: type === 'percentage' ? 70 : 60,
  });

  const trendIcon = trend > 0 ? TrendingUp : trend < 0 ? TrendingDown : Minus;
  const trendColor = trend > 0 ? 'text-green-500' : trend < 0 ? 'text-red-500' : 'text-gray-500';

  return (
    <Card className="border-zinc-800 bg-zinc-900/50 backdrop-blur-sm">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-zinc-100">{title}</CardTitle>
        {Icon && <Icon className="h-4 w-4 text-zinc-400" />}
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="text-2xl font-bold text-zinc-50">
            {KPIUtils.formatMetric(value, type)}
          </div>
          <div className={`flex items-center space-x-1 ${trendColor}`}>
            {React.createElement(trendIcon, { className: 'h-3 w-3' })}
            <span className="text-xs">{Math.abs(trend).toFixed(1)}%</span>
          </div>
        </div>
        {description && (
          <p className="text-xs text-zinc-400 mt-1">{description}</p>
        )}
        <div className="flex items-center space-x-2 mt-2">
          <Badge variant="outline" className={`${healthStatus.color} text-white border-none`}>
            {healthStatus.status}
          </Badge>
          <Progress value={type === 'percentage' ? value : (value / 1000) * 100} className="flex-1" />
        </div>
      </CardContent>
    </Card>
  );
};

/**
 * Main KPI Engine Component
 */
const KPIEngine = ({ serviceType = 'api-gateway', className = '' }) => {
  const { kpiData, loading, error, lastUpdated } = useKPIData(serviceType);

  const kpiMetrics = useMemo(() => {
    if (!kpiData) return [];

    switch (serviceType) {
      case 'api-gateway':
        return [
          {
            title: 'Requests/Second',
            value: kpiData.throughput?.requestsPerSecond || 0,
            type: 'throughput',
            trend: KPIUtils.calculateTrend(kpiData.throughput?.requestsPerSecond, 100),
            description: 'Current throughput rate',
            icon: Activity,
          },
          {
            title: 'Response Time P95',
            value: kpiData.performance?.responseTimeP95 || 0,
            type: 'milliseconds',
            trend: KPIUtils.calculateTrend(kpiData.performance?.responseTimeP95, 250),
            description: '95th percentile response time',
            icon: TrendingUp,
          },
          {
            title: 'Uptime',
            value: kpiData.reliability?.uptime || 0,
            type: 'percentage',
            trend: KPIUtils.calculateTrend(kpiData.reliability?.uptime, 99.5),
            description: 'Service availability',
            icon: CheckCircle,
          },
          {
            title: 'Auth Success Rate',
            value: kpiData.security?.authenticationSuccessRate || 0,
            type: 'percentage',
            trend: KPIUtils.calculateTrend(kpiData.security?.authenticationSuccessRate, 95),
            description: 'Authentication success rate',
            icon: CheckCircle,
          },
        ];
      case 'code-scanner':
        return [
          {
            title: 'Files Scanned/Hour',
            value: kpiData.scanning?.filesScannedPerHour || 0,
            type: 'number',
            trend: KPIUtils.calculateTrend(kpiData.scanning?.filesScannedPerHour, 500),
            description: 'Scanning throughput',
            icon: Activity,
          },
          {
            title: 'Critical Vulnerabilities',
            value: kpiData.vulnerabilities?.criticalVulnerabilities || 0,
            type: 'number',
            trend: KPIUtils.calculateTrend(kpiData.vulnerabilities?.criticalVulnerabilities, 15),
            description: 'High-priority security issues',
            icon: AlertTriangle,
          },
          {
            title: 'Scan Duration',
            value: kpiData.scanning?.scanDurationAverage || 0,
            type: 'milliseconds',
            trend: KPIUtils.calculateTrend(kpiData.scanning?.scanDurationAverage, 3000),
            description: 'Average scan time',
            icon: TrendingUp,
          },
          {
            title: 'Languages Supported',
            value: kpiData.languages?.languageDistribution?.length || 0,
            type: 'number',
            trend: 0,
            description: 'Programming languages',
            icon: CheckCircle,
          },
        ];
      default:
        return [];
    }
  }, [kpiData, serviceType]);

  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Card key={index} className="border-zinc-800 bg-zinc-900/50 backdrop-blur-sm animate-pulse">
            <CardHeader>
              <div className="h-4 bg-zinc-700 rounded w-3/4"></div>
            </CardHeader>
            <CardContent>
              <div className="h-8 bg-zinc-700 rounded w-1/2 mb-2"></div>
              <div className="h-3 bg-zinc-700 rounded w-full"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <Card className="border-red-800 bg-red-900/20 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="text-red-400 flex items-center">
            <AlertTriangle className="h-5 w-5 mr-2" />
            KPI Engine Error
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-red-300">{error}</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-zinc-100 capitalize">
          {serviceType.replace('-', ' ')} KPIs
        </h3>
        <Badge variant="outline" className="text-zinc-400 border-zinc-600">
          Last updated: {lastUpdated.toLocaleTimeString()}
        </Badge>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpiMetrics.map((metric, index) => (
          <KPIMetricCard key={index} {...metric} />
        ))}
      </div>
    </div>
  );
};

export default KPIEngine;
export { KPIUtils, useKPIData }; 