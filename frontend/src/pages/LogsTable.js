// frontend/src/components/LogsTable.js
import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TextField,
  InputAdornment,
  Chip,
  IconButton,
  Box,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Alert,
  Paper,
} from '@mui/material';
import {
  Search,
  Refresh,
  FilterList,
  Download,
  Visibility,
  Close,
} from '@mui/icons-material';
import { format } from 'date-fns';
import api from '../services/api';

const LogsTable = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    fetchLogs();
  }, [page, rowsPerPage, filter]);

  const fetchLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const apiKey = localStorage.getItem('api_key');
      if (!apiKey) {
        setError('No API key found. Please login again.');
        setLoading(false);
        return;
      }

      const params = {
        limit: rowsPerPage,
        offset: page * rowsPerPage,
      };

      const response = await api.get('/admin/logs', { params });
      
      let filteredLogs = response.data.logs || [];
      
      // Apply search filter
      if (search) {
        const searchLower = search.toLowerCase();
        filteredLogs = filteredLogs.filter(log => 
          (log.request_id && log.request_id.toLowerCase().includes(searchLower)) ||
          (log.user_id && log.user_id.toLowerCase().includes(searchLower)) ||
          (log.action && log.action.toLowerCase().includes(searchLower)) ||
          (log.reason && log.reason.toLowerCase().includes(searchLower))
        );
      }
      
      // Apply action filter
      if (filter !== 'all') {
        filteredLogs = filteredLogs.filter(log => log.action === filter);
      }
      
      setLogs(filteredLogs);
      setTotal(response.data.total || filteredLogs.length);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
      
      let errorMessage = 'Failed to load audit logs';
      if (error.response?.status === 401) {
        errorMessage = 'Session expired. Please login again.';
        localStorage.removeItem('api_key');
        window.location.href = '/login';
      } else if (error.code === 'ERR_NETWORK') {
        errorMessage = 'Cannot connect to backend server.';
      }
      
      setError(errorMessage);
      setLogs([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const csvData = logs.map(log => ({
        Timestamp: log.timestamp ? new Date(log.timestamp).toLocaleString() : '',
        'Request ID': log.request_id || '',
        'User ID': log.user_id || '',
        Action: log.action || '',
        'Risk Score': log.risk_score || 0,
        Model: log.model || '',
        'Latency (ms)': log.latency_ms || 0,
        Cost: log.cost || 0,
        Reason: log.reason || '',
      }));
      
      if (csvData.length === 0) {
        setError('No data to export');
        setExporting(false);
        return;
      }
      
      const headers = Object.keys(csvData[0]);
      const csvRows = [
        headers.join(','),
        ...csvData.map(row => headers.map(header => {
          const value = row[header];
          const escaped = String(value).replace(/"/g, '""');
          return /[,\n"]/.test(escaped) ? `"${escaped}"` : escaped;
        }).join(','))
      ];
      
      const csvString = csvRows.join('\n');
      const blob = new Blob([csvString], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `audit-logs-${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
    } catch (error) {
      console.error('Export failed:', error);
      setError('Failed to export logs');
    } finally {
      setExporting(false);
    }
  };

  const handleViewDetails = (log) => {
    setSelectedLog(log);
    setDialogOpen(true);
  };

  const handleCloseDialog = () => {
    setDialogOpen(false);
    setSelectedLog(null);
  };

  const getActionColor = (action) => {
    switch (action) {
      case 'ALLOW':
        return 'success';
      case 'BLOCK':
        return 'error';
      case 'REVIEW':
        return 'warning';
      default:
        return 'default';
    }
  };

  const getRiskColor = (score) => {
    if (score > 70) return 'error';
    if (score > 40) return 'warning';
    return 'success';
  };

  const getRiskLabel = (score) => {
    if (score > 70) return 'High';
    if (score > 40) return 'Medium';
    return 'Low';
  };

  const handleSearchKeyPress = (e) => {
    if (e.key === 'Enter') {
      fetchLogs();
    }
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" sx={{ fontWeight: 700 }}>
          Audit Logs
        </Typography>
        <Box>
          <IconButton onClick={fetchLogs} disabled={loading} title="Refresh">
            <Refresh />
          </IconButton>
          <IconButton onClick={handleExport} disabled={loading || exporting || logs.length === 0} title="Export to CSV">
            <Download />
          </IconButton>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Card>
        <CardContent>
          <Box display="flex" gap={2} mb={3}>
            <TextField
              placeholder="Search by Request ID, User ID, Action, or Reason..."
              size="small"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyPress={handleSearchKeyPress}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Search />
                  </InputAdornment>
                ),
                endAdornment: search && (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setSearch('')}>
                      <Close fontSize="small" />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{ flexGrow: 1 }}
            />
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Action</InputLabel>
              <Select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                label="Action"
              >
                <MenuItem value="all">All Actions</MenuItem>
                <MenuItem value="ALLOW">Allow Only</MenuItem>
                <MenuItem value="BLOCK">Block Only</MenuItem>
              </Select>
            </FormControl>
            <IconButton onClick={fetchLogs} disabled={loading} title="Apply Filters">
              <FilterList />
            </IconButton>
          </Box>

          <TableContainer component={Paper}>
            <Table size="medium">
              <TableHead>
                <TableRow sx={{ backgroundColor: 'action.hover' }}>
                  <TableCell sx={{ fontWeight: 600 }}>Timestamp</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Request ID</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>User ID</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Action</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Risk Score</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Model</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Latency</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Cost</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Details</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={9} align="center" sx={{ py: 4 }}>
                      <Typography color="textSecondary">Loading audit logs...</Typography>
                    </TableCell>
                  </TableRow>
                ) : logs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} align="center" sx={{ py: 4 }}>
                      <Typography color="textSecondary">
                        {search || filter !== 'all' 
                          ? 'No logs match your filters' 
                          : 'No audit logs found. Make some API calls to see logs here.'}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  logs.map((log, index) => (
                    <TableRow key={log.id || index} hover>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                          {log.timestamp ? format(new Date(log.timestamp), 'yyyy-MM-dd HH:mm:ss') : '-'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={log.request_id?.substring(0, 12) || 'N/A'}
                          size="small"
                          variant="outlined"
                          sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                          {log.user_id?.substring(0, 12) || '-'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={log.action || 'UNKNOWN'}
                          size="small"
                          color={getActionColor(log.action)}
                          sx={{ fontWeight: 600 }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={`${log.risk_score || 0} (${getRiskLabel(log.risk_score || 0)})`}
                          size="small"
                          color={getRiskColor(log.risk_score || 0)}
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{log.model || '-'}</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{Math.round(log.latency_ms || 0)}ms</Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">${(log.cost || 0).toFixed(4)}</Typography>
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleViewDetails(log)}
                          title="View Details"
                        >
                          <Visibility fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>

          <TablePagination
            rowsPerPageOptions={[25, 50, 100]}
            component="div"
            count={total}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={(e, newPage) => setPage(newPage)}
            onRowsPerPageChange={(e) => {
              setRowsPerPage(parseInt(e.target.value, 10));
              setPage(0);
            }}
          />
        </CardContent>
      </Card>

      {/* Log Details Dialog */}
      <Dialog open={dialogOpen} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          Log Details
          <IconButton
            aria-label="close"
            onClick={handleCloseDialog}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <Close />
          </IconButton>
        </DialogTitle>
        <DialogContent dividers>
          {selectedLog && (
            <Box>
              <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                Request ID
              </Typography>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', mb: 2 }}>
                {selectedLog.request_id}
              </Typography>

              <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                Timestamp
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                {selectedLog.timestamp ? new Date(selectedLog.timestamp).toLocaleString() : '-'}
              </Typography>

              <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                Action
              </Typography>
              <Chip
                label={selectedLog.action}
                color={getActionColor(selectedLog.action)}
                sx={{ mb: 2 }}
              />

              <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                Risk Score
              </Typography>
              <Chip
                label={`${selectedLog.risk_score} - ${getRiskLabel(selectedLog.risk_score)}`}
                color={getRiskColor(selectedLog.risk_score)}
                sx={{ mb: 2 }}
              />

              <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                Reason
              </Typography>
              <Paper variant="outlined" sx={{ p: 2, mb: 2, bgcolor: 'action.hover' }}>
                <Typography variant="body2">
                  {selectedLog.reason || 'No reason provided'}
                </Typography>
              </Paper>

              <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                Performance
              </Typography>
              <Box display="flex" gap={3} mb={2}>
                <Box>
                  <Typography variant="caption" color="textSecondary">Latency</Typography>
                  <Typography variant="body2">{Math.round(selectedLog.latency_ms || 0)}ms</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="textSecondary">Cost</Typography>
                  <Typography variant="body2">${(selectedLog.cost || 0).toFixed(4)}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="textSecondary">Model</Typography>
                  <Typography variant="body2">{selectedLog.model || '-'}</Typography>
                </Box>
              </Box>

              <Typography variant="subtitle2" color="textSecondary" gutterBottom>
                User ID
              </Typography>
              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                {selectedLog.user_id || '-'}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default LogsTable;