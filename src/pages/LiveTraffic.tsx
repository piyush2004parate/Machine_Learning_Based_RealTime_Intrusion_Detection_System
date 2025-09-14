import React, { useState, useEffect } from 'react';
import { DataTable } from '../components/UI/DataTable';
import { NetworkTraffic } from '../types';
import { generateMockTraffic } from '../data/mockData';
import { format } from 'date-fns';
import { RefreshCw, Play, Pause } from 'lucide-react';

export const LiveTraffic: React.FC = () => {
  const [traffic, setTraffic] = useState<NetworkTraffic[]>(generateMockTraffic());
  const [isAutoRefresh, setIsAutoRefresh] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(new Date());

  const refreshData = () => {
    setTraffic(generateMockTraffic());
    setLastUpdate(new Date());
  };

  useEffect(() => {
    if (!isAutoRefresh) return;

    const interval = setInterval(refreshData, 3000);
    return () => clearInterval(interval);
  }, [isAutoRefresh]);

  const getStatusBadge = (status: NetworkTraffic['status']) => {
    const colors = {
      Normal: 'bg-green-500',
      Anomalous: 'bg-yellow-500',
      Blocked: 'bg-red-500',
    };

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium text-white ${colors[status]}`}>
        {status}
      </span>
    );
  };

  const getSeverityBadge = (severity?: NetworkTraffic['severity']) => {
    if (!severity) return null;

    const colors = {
      Low: 'bg-blue-500',
      Medium: 'bg-yellow-500',
      High: 'bg-orange-500',
      Critical: 'bg-red-500',
    };

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium text-white ${colors[severity]}`}>
        {severity}
      </span>
    );
  };

  const columns = [
    {
      key: 'timestamp' as keyof NetworkTraffic,
      header: 'Time',
      render: (item: NetworkTraffic) => format(item.timestamp, 'HH:mm:ss'),
      sortable: true,
    },
    {
      key: 'sourceIp' as keyof NetworkTraffic,
      header: 'Source IP',
      sortable: true,
    },
    {
      key: 'destinationIp' as keyof NetworkTraffic,
      header: 'Destination IP',
      sortable: true,
    },
    {
      key: 'protocol' as keyof NetworkTraffic,
      header: 'Protocol',
      sortable: true,
    },
    {
      key: 'bytes' as keyof NetworkTraffic,
      header: 'Bytes',
      render: (item: NetworkTraffic) => item.bytes.toLocaleString(),
      sortable: true,
    },
    {
      key: 'status' as keyof NetworkTraffic,
      header: 'Status',
      render: (item: NetworkTraffic) => getStatusBadge(item.status),
      sortable: true,
    },
    {
      key: 'severity' as keyof NetworkTraffic,
      header: 'Severity',
      render: (item: NetworkTraffic) => getSeverityBadge(item.severity),
      sortable: false,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Live Network Traffic</h2>
          <p className="text-gray-400">
            Last updated: {format(lastUpdate, 'HH:mm:ss')}
          </p>
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => setIsAutoRefresh(!isAutoRefresh)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
              isAutoRefresh
                ? 'bg-green-600 hover:bg-green-700 text-white'
                : 'bg-gray-600 hover:bg-gray-700 text-white'
            }`}
          >
            {isAutoRefresh ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            <span>{isAutoRefresh ? 'Auto-Refresh ON' : 'Auto-Refresh OFF'}</span>
          </button>

          <button
            onClick={refreshData}
            className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <div className="mb-4">
          <div className="flex items-center space-x-4 text-sm text-gray-400">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              <span>Normal ({traffic.filter(t => t.status === 'Normal').length})</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
              <span>Anomalous ({traffic.filter(t => t.status === 'Anomalous').length})</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-red-500 rounded-full"></div>
              <span>Blocked ({traffic.filter(t => t.status === 'Blocked').length})</span>
            </div>
          </div>
        </div>

        <DataTable
          data={traffic}
          columns={columns}
          searchable
          pageSize={15}
        />
      </div>
    </div>
  );
};