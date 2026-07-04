// frontend/src/components/SecurityPanel.js
import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Switch,
  FormControlLabel,
  Button,
  Slider,
  TextField,
  Alert,
  Chip,
  List,
  ListItem,
  ListItemText,
  Divider,
} from '@mui/material';
import {
  Security,
  Block,
  CheckCircle,
  Warning,
  Settings,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import api from '../services/api';

const SecurityPanel = () => {
  const [settings, setSettings] = useState({
    blockThreshold: 70,
    reviewThreshold: 40,
    enablePiiRedaction: true,
    enableSemanticAnalysis: true,
    enableRateLimiting: true,
    webhookUrl: '',
  });
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({});

  useEffect(() => {
    fetchSecuritySettings();
    fetchThreatStats();
  }, []);

  const fetchSecuritySettings = async () => {
    try {
      const response = await api.get('/admin/security/settings');
      setSettings(response.data);
    } catch (error) {
      console.error('Failed to fetch security settings:', error);
    }
  };

  const fetchThreatStats = async () => {
    try {
      const response = await api.get('/admin/security/threats');
      setThreats(response.data.threats);
      setStats(response.data.stats);
    } catch (error) {
      console.error('Failed to fetch threat stats:', error);
    }
  };

  const handleSaveSettings = async () => {
    try {
      await api.post('/admin/security/settings', settings);
      // Show success message
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Security Controls
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Detection
              </Typography>
              <Box sx={{ mb: 3 }}>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Block Threshold
                </Typography>
                <Slider
                  value={settings.blockThreshold}
                  onChange={(e, val) =>
                    setSettings({ ...settings, blockThreshold: val })
                  }
                  valueLabelDisplay="auto"
                  step={5}
                  marks
                  min={0}
                  max={100}
                  sx={{ color: '#ff006e' }}
                />
              </Box>

              <Box sx={{ mb: 3 }}>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  Review Threshold
                </Typography>
                <Slider
                  value={settings.reviewThreshold}
                  onChange={(e, val) =>
                    setSettings({ ...settings, reviewThreshold: val })
                  }
                  valueLabelDisplay="auto"
                  step={5}
                  marks
                  min={0}
                  max={100}
                  sx={{ color: '#ff9e00' }}
                />
              </Box>

              <FormControlLabel
                control={
                  <Switch
                    checked={settings.enablePiiRedaction}
                    onChange={(e) =>
                      setSettings({ ...settings, enablePiiRedaction: e.target.checked })
                    }
                  />
                }
                label="Enable PII Redaction"
              />

              <FormControlLabel
                control={
                  <Switch
                    checked={settings.enableSemanticAnalysis}
                    onChange={(e) =>
                      setSettings({ ...settings, enableSemanticAnalysis: e.target.checked })
                    }
                  />
                }
                label="Enable Semantic Analysis"
              />

              <FormControlLabel
                control={
                  <Switch
                    checked={settings.enableRateLimiting}
                    onChange={(e) =>
                      setSettings({ ...settings, enableRateLimiting: e.target.checked })
                    }
                  />
                }
                label="Enable Rate Limiting"
              />

              <TextField
                fullWidth
                label="Webhook URL"
                value={settings.webhookUrl}
                onChange={(e) =>
                  setSettings({ ...settings, webhookUrl: e.target.value })
                }
                margin="normal"
                size="small"
                placeholder="https://your-domain.com/webhook"
              />

              <Button
                variant="contained"
                onClick={handleSaveSettings}
                sx={{ mt: 2 }}
              >
                Save Settings
              </Button>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Security Overview
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Box textAlign="center">
                    <Typography variant="h3" color="error">
                      {stats.totalBlocked || 0}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      Total Threats Blocked
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box textAlign="center">
                    <Typography variant="h3" color="warning">
                      {stats.activeAlerts || 0}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      Active Alerts
                    </Typography>
                  </Box>
                </Grid>
              </Grid>

              <Box sx={{ mt: 3, height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={stats.threatTrend || []}>
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Line
                      type="monotone"
                      dataKey="threats"
                      stroke="#ff006e"
                      name="Threats"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Threats
              </Typography>
              <List>
                {threats.map((threat, index) => (
                  <React.Fragment key={index}>
                    <ListItem>
                      <ListItemText
                        primary={
                          <Box display="flex" alignItems="center" gap={1}>
                            <Warning color="error" />
                            <Typography variant="body1">{threat.type}</Typography>
                            <Chip
                              label={`Risk: ${threat.riskScore}`}
                              size="small"
                              color="error"
                            />
                          </Box>
                        }
                        secondary={
                          <>
                            <Typography variant="caption" color="textSecondary">
                              {threat.timestamp}
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 1 }}>
                              {threat.details}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                    {index < threats.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default SecurityPanel;