// frontend/src/services/api.js
import axios from 'axios';

let API_URL = process.env.REACT_APP_API_URL || 'https://ai-firewall-production.up.railway.app';
API_URL = API_URL.replace(/\/$/, '');

const api = axios.create({
  baseURL: `${API_URL}/v1`,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('api_key');
    if (token) {
      config.headers['X-API-Key'] = token;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const isAuthRequest = error.config.url.includes('/auth/');
      
      // Only redirect to login if it's NOT an auth request and we get a 401
      if (error.response.status === 401 && !isAuthRequest) {
        localStorage.removeItem('api_key');
        localStorage.removeItem('user_id');
        localStorage.removeItem('user_email');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;
