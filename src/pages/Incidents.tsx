import React, { useState } from 'react';
import { DataTable } from '../components/UI/DataTable';
import { Modal } from '../components/UI/Modal';
import { ThreatIncident } from '../types';
import { generateMockIncidents } from '../data/mockData';
import { format } from 'date-fns';
import { Eye, Shield, Ban, AlertTriangle, CheckCircle } from 'lucide-react';
import { useToast } from '../hooks/useToast';

export const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<ThreatIncident[]>(generateMockIncidents());
  const [selectedIncident, setSelectedIncident] = useState<ThreatIncident | null>(null);
  const { showToast } = useToast();

  const getSeverityBadge = (severity: ThreatIncident['severity']) => {
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

  const getStatusBadge = (status: ThreatIncident['status']) => {
    const colors = {
      Active: 'bg-red-500',
      Blocked: 'bg-orange-500',
      Investigating: 'bg-yellow-500',
      Resolved: 'bg-green-500',
      'False Positive': 'bg-gray-500',
    };

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium text-white ${colors[status]}`}>
        {status}
      </span>
    );
  };

  const handleBlockIp = (incident: ThreatIncident) => {
    setIncidents(prev =>
      prev.map(i =>
        i.id === incident.id ? { ...i, status: 'Blocked' } : i
      )
    );
    showToast('success', `IP ${incident.sourceIp} has been blocked`);
  };

  const handleIsolateDevice = (incident: ThreatIncident) => {
    setIncidents(prev =>
      prev.map(i =>
        i.id === incident.id ? { ...i, status: 'Blocked' } : i
      )
    );
    showToast('success', `Device ${incident.sourceIp} has been isolated`);
  };

  const handleMarkFalsePositive = (incident: ThreatIncident) => {
    setIncidents(prev =>
      prev.map(i =>
        i.id === incident.id ? { ...i, status: 'False Positive' } : i
      )
    );
    showToast('info', 'Incident marked as false positive');
  };

  const columns = [
    {
      key: 'id' as keyof ThreatIncident,
      header: 'ID',
      render: (item: ThreatIncident) => item.id.split('-')[1]?.toUpperCase(),
      sortable: true,
    },
    {
      key: 'timestamp' as keyof ThreatIncident,
      header: 'Time',
      render: (item: ThreatIncident) => format(item.timestamp, 'MMM dd, HH:mm'),
      sortable: true,
    },
    {
      key: 'sourceIp' as keyof ThreatIncident,
      header: 'Source IP',
      sortable: true,
    },
    {
      key: 'destinationIp' as keyof ThreatIncident,
      header: 'Destination IP',
      sortable: true,
    },
    {
      key: 'threatType' as keyof ThreatIncident,
      header: 'Threat Type',
      sortable: true,
    },
    {
      key: 'severity' as keyof ThreatIncident,
      header: 'Severity',
      render: (item: ThreatIncident) => getSeverityBadge(item.severity),
      sortable: true,
    },
    {
      key: 'status' as keyof ThreatIncident,
      header: 'Status',
      render: (item: ThreatIncident) => getStatusBadge(item.status),
      sortable: true,
    },
    {
      key: 'confidence' as keyof ThreatIncident,
      header: 'Confidence',
      render: (item: ThreatIncident) => `${item.confidence}%`,
      sortable: true,
    },
    {
      key: 'id' as keyof ThreatIncident,
      header: 'Actions',
      render: (item: ThreatIncident) => (
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setSelectedIncident(item)}
            className="p-1 text-blue-400 hover:text-blue-300 transition-colors"
            title="View Details"
          >
            <Eye className="h-4 w-4" />
          </button>
          {item.status === 'Active' && (
            <>
              <button
                onClick={() => handleBlockIp(item)}
                className="p-1 text-red-400 hover:text-red-300 transition-colors"
                title="Block IP"
              >
                <Ban className="h-4 w-4" />
              </button>
              <button
                onClick={() => handleIsolateDevice(item)}
                className="p-1 text-orange-400 hover:text-orange-300 transition-colors"
                title="Isolate Device"
              >
                <Shield className="h-4 w-4" />
              </button>
              <button
                onClick={() => handleMarkFalsePositive(item)}
                className="p-1 text-gray-400 hover:text-gray-300 transition-colors"
                title="Mark as False Positive"
              >
                <CheckCircle className="h-4 w-4" />
              </button>
            </>
          )}
        </div>
      ),
      sortable: false,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Security Incidents</h2>
          <p className="text-gray-400">Detected threats and anomalous activities</p>
        </div>

        <div className="flex items-center space-x-4 text-sm text-gray-400">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <span>Active ({incidents.filter(i => i.status === 'Active').length})</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
            <span>Blocked ({incidents.filter(i => i.status === 'Blocked').length})</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span>Resolved ({incidents.filter(i => i.status === 'Resolved').length})</span>
          </div>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <DataTable
          data={incidents}
          columns={columns}
          searchable
          pageSize={10}
        />
      </div>

      <Modal
        isOpen={!!selectedIncident}
        onClose={() => setSelectedIncident(null)}
        title="Incident Details"
        size="lg"
      >
        {selectedIncident && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Incident ID
                </label>
                <p className="text-white">{selectedIncident.id}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Timestamp
                </label>
                <p className="text-white">{format(selectedIncident.timestamp, 'PPpp')}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Source IP
                </label>
                <p className="text-white font-mono">{selectedIncident.sourceIp}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Destination IP
                </label>
                <p className="text-white font-mono">{selectedIncident.destinationIp}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Threat Type
                </label>
                <p className="text-white">{selectedIncident.threatType}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Confidence Level
                </label>
                <p className="text-white">{selectedIncident.confidence}%</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Severity
                </label>
                <div>{getSeverityBadge(selectedIncident.severity)}</div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Status
                </label>
                <div>{getStatusBadge(selectedIncident.status)}</div>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">
                Description
              </label>
              <p className="text-white bg-gray-700 p-3 rounded-lg">
                {selectedIncident.description}
              </p>
            </div>

            {selectedIncident.status === 'Active' && (
              <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-700">
                <button
                  onClick={() => {
                    handleMarkFalsePositive(selectedIncident);
                    setSelectedIncident(null);
                  }}
                  className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
                >
                  Mark as False Positive
                </button>
                <button
                  onClick={() => {
                    handleIsolateDevice(selectedIncident);
                    setSelectedIncident(null);
                  }}
                  className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors"
                >
                  <Shield className="h-4 w-4 mr-2 inline" />
                  Isolate Device
                </button>
                <button
                  onClick={() => {
                    handleBlockIp(selectedIncident);
                    setSelectedIncident(null);
                  }}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                >
                  <Ban className="h-4 w-4 mr-2 inline" />
                  Block IP
                </button>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};