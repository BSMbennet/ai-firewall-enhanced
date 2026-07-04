// frontend/src/store/slices/dashboardSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../services/api';

export const fetchStats = createAsyncThunk(
  'dashboard/fetchStats',
  async () => {
    const response = await api.get('/dashboard/stats');
    return response.data;
  }
);

export const fetchDailyStats = createAsyncThunk(
  'dashboard/fetchDailyStats',
  async () => {
    const response = await api.get('/dashboard/daily-stats');
    return response.data;
  }
);

export const fetchAlerts = createAsyncThunk(
  'dashboard/fetchAlerts',
  async () => {
    const response = await api.get('/dashboard/alerts');
    return response.data;
  }
);

const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState: {
    stats: {},
    dailyStats: [],
    alerts: [],
    loading: false,
    error: null,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchStats.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchStats.fulfilled, (state, action) => {
        state.loading = false;
        state.stats = action.payload;
      })
      .addCase(fetchStats.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      .addCase(fetchDailyStats.fulfilled, (state, action) => {
        state.dailyStats = action.payload;
      })
      .addCase(fetchAlerts.fulfilled, (state, action) => {
        state.alerts = action.payload;
      });
  },
});

export default dashboardSlice.reducer;
