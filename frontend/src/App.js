import React, { useState, useEffect, createContext, useContext } from 'react';
import { User, LogOut, Menu, X, Mail, Lock, UserCircle, Shield } from 'lucide-react';

// Auth Context
const AuthContext = createContext(null);

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};

// API Configuration - CONNECTS TO BACKEND
const API_URL = 'http://localhost:3001/api';

const api = {
  async login(email, password) {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Login failed');
    }
    
    const data = await response.json();
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    return data;
  },

  async signup(name, email, password) {
    const response = await fetch(`${API_URL}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Signup failed');
    }
    
    const data = await response.json();
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    return data;
  },

  async getProfile() {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_URL}/profile`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) throw new Error('Failed to fetch profile');
    return response.json();
  },

  async updateProfile(data) {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_URL}/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) throw new Error('Failed to update profile');
    const updated = await response.json();
    localStorage.setItem('user', JSON.stringify(updated));
    return updated;
  },

  logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  }
};

// Auth Provider
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    
    if (token && savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    const {user} = await api.login(email, password);
    setUser(user);
    return user;
  };

  const signup = async (name, email, password) => {
    const { user } = await api.signup(name, email, password);
    setUser(user);
    return user;
  };

  const logout = () => {
    api.logout();
    setUser(null);
  };

  const updateUser = async (data) => {
    const updated = await api.updateProfile(data);
    setUser(updated);
    return updated;
  };

  return (
    <AuthContext.Provider value={{ user, login, signup, logout, updateUser, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

// Login Component
const LoginForm = ({ onSwitchToSignup }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState('');
  const [hoveredInput, setHoveredInput] = useState(null);
  const { login } = useAuth();

  const validate = () => {
    const newErrors = {};
    
    if (!email) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(email)) {
      newErrors.email = 'Email is invalid';
    }
    
    if (!password) {
      newErrors.password = 'Password is required';
    } else if (password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }
    
    return newErrors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError('');
    
    const newErrors = validate();
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    
    setErrors({});
    setLoading(true);
    
    try {
      await login(email, password);
    } catch (err) {
      setApiError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 p-4">
      <div className="w-full max-w-md bg-white rounded-3xl shadow-2xl p-10 border border-gray-200 hover:shadow-[0_20px_60px_rgba(0,0,0,0.2)] transition-all duration-500 transform hover:scale-[1.02]">
        <div className="flex justify-center mb-8">
          <div className="bg-gradient-to-br from-blue-500 via-blue-600 to-purple-700 p-5 rounded-2xl shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:scale-110">
            <Shield className="w-8 h-8 text-white" />
          </div>
        </div>
        
        <h2 className="text-4xl font-bold text-center mb-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
          Welcome Back
        </h2>
        <p className="text-center text-gray-500 mb-8 text-lg font-medium">Sign in to your account</p>
        
        {apiError && (
          <div className="mb-6 p-4 bg-gradient-to-r from-red-50 to-pink-50 border border-red-300 text-red-700 rounded-xl text-sm font-medium shadow-md animate-slideUp">
            ⚠️ {apiError}
          </div>
        )}
        
        <div className="space-y-6">
          <div
            onMouseEnter={() => setHoveredInput('email')}
            onMouseLeave={() => setHoveredInput(null)}
            className={`transform transition-all duration-300 ${hoveredInput === 'email' ? 'scale-105' : 'scale-100'}`}
          >
            <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wide">
              Email Address
            </label>
            <div className={`relative transition-all duration-300 ${hoveredInput === 'email' ? 'drop-shadow-lg' : ''}`}>
              <Mail className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${hoveredInput === 'email' ? 'text-blue-600 scale-110' : 'text-gray-400'}`} />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={`w-full pl-12 pr-4 py-4 border-2 ${errors.email ? 'border-red-400' : hoveredInput === 'email' ? 'border-blue-500' : 'border-gray-300'} rounded-xl focus:ring-0 focus:border-blue-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white`}
                placeholder="you@example.com"
              />
            </div>
            {errors.email && <p className="mt-2 text-sm text-red-600 font-medium">✗ {errors.email}</p>}
          </div>
          
          <div
            onMouseEnter={() => setHoveredInput('password')}
            onMouseLeave={() => setHoveredInput(null)}
            className={`transform transition-all duration-300 ${hoveredInput === 'password' ? 'scale-105' : 'scale-100'}`}
          >
            <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wide">
              Password
            </label>
            <div className={`relative transition-all duration-300 ${hoveredInput === 'password' ? 'drop-shadow-lg' : ''}`}>
              <Lock className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${hoveredInput === 'password' ? 'text-blue-600 scale-110' : 'text-gray-400'}`} />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={`w-full pl-12 pr-4 py-4 border-2 ${errors.password ? 'border-red-400' : hoveredInput === 'password' ? 'border-blue-500' : 'border-gray-300'} rounded-xl focus:ring-0 focus:border-blue-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white`}
                placeholder="••••••••"
              />
            </div>
            {errors.password && <p className="mt-2 text-sm text-red-600 font-medium">✗ {errors.password}</p>}
          </div>
          
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="w-full bg-gradient-to-r from-blue-600 via-blue-700 to-purple-700 text-white py-4 rounded-xl font-bold text-lg hover:from-blue-700 hover:via-blue-800 hover:to-purple-800 transition-all transform hover:scale-[1.05] hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed shadow-lg active:scale-95 mt-2"
          >
            {loading ? '⏳ Signing in...' : '🔐 Sign In'}
          </button>
        </div>
        
        <div className="mt-8 pt-6 border-t border-gray-200">
          <p className="text-center text-gray-600 text-sm">
            Don't have an account?{' '}
            <button
              onClick={onSwitchToSignup}
              className="text-blue-600 font-bold hover:text-blue-700 hover:underline transition-all duration-200"
            >
              Sign up here
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

// Signup Component
const SignupForm = ({ onSwitchToLogin }) => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState('');
  const [hoveredInput, setHoveredInput] = useState(null);
  const { signup } = useAuth();

  const validate = () => {
    const newErrors = {};
    
    if (!name) {
      newErrors.name = 'Name is required';
    } else if (name.length < 2) {
      newErrors.name = 'Name must be at least 2 characters';
    }
    
    if (!email) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(email)) {
      newErrors.email = 'Email is invalid';
    }
    
    if (!password) {
      newErrors.password = 'Password is required';
    } else if (password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      newErrors.password = 'Password must contain uppercase, lowercase, and number';
    }
    
    if (!confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (password !== confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }
    
    return newErrors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError('');
    
    const newErrors = validate();
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    
    setErrors({});
    setLoading(true);
    
    try {
      await signup(name, email, password);
    } catch (err) {
      setApiError(err.message || 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 p-4">
      <div className="w-full max-w-md bg-white rounded-3xl shadow-2xl p-10 border border-gray-200 hover:shadow-[0_20px_60px_rgba(0,0,0,0.2)] transition-all duration-500 transform hover:scale-[1.02]">
        <div className="flex justify-center mb-8">
          <div className="bg-gradient-to-br from-green-500 via-emerald-600 to-teal-700 p-5 rounded-2xl shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:scale-110">
            <UserCircle className="w-8 h-8 text-white" />
          </div>
        </div>
        
        <h2 className="text-4xl font-bold text-center mb-3 bg-gradient-to-r from-green-600 via-emerald-600 to-teal-600 bg-clip-text text-transparent">
          Create Account
        </h2>
        <p className="text-center text-gray-500 mb-8 text-lg font-medium">Join us today</p>
        
        {apiError && (
          <div className="mb-6 p-4 bg-gradient-to-r from-red-50 to-pink-50 border border-red-300 text-red-700 rounded-xl text-sm font-medium shadow-md animate-slideUp">
            ⚠️ {apiError}
          </div>
        )}
        
        <div className="space-y-6">
          <div
            onMouseEnter={() => setHoveredInput('name')}
            onMouseLeave={() => setHoveredInput(null)}
            className={`transform transition-all duration-300 ${hoveredInput === 'name' ? 'scale-105' : 'scale-100'}`}
          >
            <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wide">
              Full Name
            </label>
            <div className={`relative transition-all duration-300 ${hoveredInput === 'name' ? 'drop-shadow-lg' : ''}`}>
              <User className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${hoveredInput === 'name' ? 'text-green-600 scale-110' : 'text-gray-400'}`} />
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className={`w-full pl-12 pr-4 py-4 border-2 ${errors.name ? 'border-red-400' : hoveredInput === 'name' ? 'border-green-500' : 'border-gray-300'} rounded-xl focus:ring-0 focus:border-green-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white`}
                placeholder="John Doe"
              />
            </div>
            {errors.name && <p className="mt-2 text-sm text-red-600 font-medium">✗ {errors.name}</p>}
          </div>
          
          <div
            onMouseEnter={() => setHoveredInput('email')}
            onMouseLeave={() => setHoveredInput(null)}
            className={`transform transition-all duration-300 ${hoveredInput === 'email' ? 'scale-105' : 'scale-100'}`}
          >
            <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wide">
              Email Address
            </label>
            <div className={`relative transition-all duration-300 ${hoveredInput === 'email' ? 'drop-shadow-lg' : ''}`}>
              <Mail className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${hoveredInput === 'email' ? 'text-green-600 scale-110' : 'text-gray-400'}`} />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={`w-full pl-12 pr-4 py-4 border-2 ${errors.email ? 'border-red-400' : hoveredInput === 'email' ? 'border-green-500' : 'border-gray-300'} rounded-xl focus:ring-0 focus:border-green-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white`}
                placeholder="you@example.com"
              />
            </div>
            {errors.email && <p className="mt-2 text-sm text-red-600 font-medium">✗ {errors.email}</p>}
          </div>
          
          <div
            onMouseEnter={() => setHoveredInput('password')}
            onMouseLeave={() => setHoveredInput(null)}
            className={`transform transition-all duration-300 ${hoveredInput === 'password' ? 'scale-105' : 'scale-100'}`}
          >
            <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wide">
              Password
            </label>
            <div className={`relative transition-all duration-300 ${hoveredInput === 'password' ? 'drop-shadow-lg' : ''}`}>
              <Lock className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${hoveredInput === 'password' ? 'text-green-600 scale-110' : 'text-gray-400'}`} />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={`w-full pl-12 pr-4 py-4 border-2 ${errors.password ? 'border-red-400' : hoveredInput === 'password' ? 'border-green-500' : 'border-gray-300'} rounded-xl focus:ring-0 focus:border-green-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white`}
                placeholder="••••••••"
              />
            </div>
            {errors.password && <p className="mt-2 text-sm text-red-600 font-medium">✗ {errors.password}</p>}
          </div>
          
          <div
            onMouseEnter={() => setHoveredInput('confirm')}
            onMouseLeave={() => setHoveredInput(null)}
            className={`transform transition-all duration-300 ${hoveredInput === 'confirm' ? 'scale-105' : 'scale-100'}`}
          >
            <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wide">
              Confirm Password
            </label>
            <div className={`relative transition-all duration-300 ${hoveredInput === 'confirm' ? 'drop-shadow-lg' : ''}`}>
              <Lock className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${hoveredInput === 'confirm' ? 'text-green-600 scale-110' : 'text-gray-400'}`} />
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className={`w-full pl-12 pr-4 py-4 border-2 ${errors.confirmPassword ? 'border-red-400' : hoveredInput === 'confirm' ? 'border-green-500' : 'border-gray-300'} rounded-xl focus:ring-0 focus:border-green-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white`}
                placeholder="••••••••"
              />
            </div>
            {errors.confirmPassword && <p className="mt-2 text-sm text-red-600 font-medium">✗ {errors.confirmPassword}</p>}
          </div>
          
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="w-full bg-gradient-to-r from-green-600 via-emerald-700 to-teal-700 text-white py-4 rounded-xl font-bold text-lg hover:from-green-700 hover:via-emerald-800 hover:to-teal-800 transition-all transform hover:scale-[1.05] hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed shadow-lg active:scale-95 mt-2"
          >
            {loading ? '⏳ Creating Account...' : '✨ Sign Up'}
          </button>
        </div>
        
        <div className="mt-8 pt-6 border-t border-gray-200">
          <p className="text-center text-gray-600 text-sm">
            Already have an account?{' '}
            <button
              onClick={onSwitchToLogin}
              className="text-green-600 font-bold hover:text-green-700 hover:underline transition-all duration-200"
            >
              Sign in here
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const { user, logout, updateUser } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const [formData, setFormData] = useState({ name: '', email: '' });
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (user) {
      setFormData({ name: user.name, email: user.email });
    }
  }, [user]);

  const handleUpdate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setSuccess('');
    
    try {
      await updateUser(formData);
      setSuccess('Profile updated successfully!');
      setEditing(false);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      alert('Update failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 p-4 md:p-8">
      {/* Navigation */}
      <nav className="bg-white shadow-xl border border-gray-200 rounded-2xl mb-8 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3 group cursor-pointer transition-all duration-300 hover:scale-105">
              <div className="bg-gradient-to-br from-blue-500 via-blue-600 to-purple-700 p-3 rounded-xl shadow-lg group-hover:shadow-2xl transition-all duration-300">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <span className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">Auth App</span>
            </div>
            
            <div className="hidden md:flex items-center space-x-4">
              <div className="flex items-center space-x-3 px-5 py-3 bg-gradient-to-r from-gray-50 to-gray-100 rounded-xl hover:from-gray-100 hover:to-gray-200 transition-all duration-300 shadow-md hover:shadow-lg group">
                <User className="w-5 h-5 text-blue-600 group-hover:scale-110 transition-transform duration-300" />
                <div>
                  <p className="text-sm font-bold text-gray-900">{user?.name}</p>
                  <p className="text-xs text-gray-500">{user?.role || 'User'}</p>
                </div>
              </div>
              <button
                onClick={logout}
                className="flex items-center space-x-2 px-5 py-3 bg-gradient-to-r from-red-50 to-pink-50 text-red-600 rounded-xl hover:from-red-100 hover:to-pink-100 transition-all duration-300 shadow-md hover:shadow-lg font-semibold group transform hover:scale-105 active:scale-95"
              >
                <LogOut className="w-4 h-4 group-hover:animate-pulse" />
                <span>Logout</span>
              </button>
            </div>
            
            <div className="md:hidden flex items-center">
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="p-2 rounded-lg text-gray-600 hover:bg-gray-100 transition-all duration-300"
              >
                {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>
        </div>
        
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-gray-200 bg-white rounded-b-2xl">
            <div className="px-6 py-4 space-y-3">
              <div className="flex items-center space-x-3 px-4 py-3 bg-gradient-to-r from-gray-50 to-gray-100 rounded-xl">
                <User className="w-5 h-5 text-blue-600" />
                <div>
                  <p className="text-sm font-semibold text-gray-900">{user?.name}</p>
                  <p className="text-xs text-gray-500">{user?.role || 'User'}</p>
                </div>
              </div>
              <button
                onClick={logout}
                className="w-full flex items-center justify-center space-x-2 px-4 py-3 bg-gradient-to-r from-red-50 to-pink-50 text-red-600 rounded-xl hover:from-red-100 hover:to-pink-100 transition-all font-semibold"
              >
                <LogOut className="w-4 h-4" />
                <span>Logout</span>
              </button>
            </div>
          </div>
        )}
      </nav>
      
      {/* Main Content */}
      <div className="max-w-4xl mx-auto">
        <div className="mb-10 text-center">
          <h1 className="text-5xl font-bold text-gray-900 mb-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
            Welcome, {user?.name}! 👋
          </h1>
          <p className="text-xl text-gray-600 font-medium">Manage your profile settings below</p>
        </div>
        
        {success && (
          <div className="mb-8 p-5 bg-gradient-to-r from-green-50 to-emerald-50 border-2 border-green-300 text-green-700 rounded-xl text-lg font-bold shadow-lg animate-slideUp">
            ✨ {success}
          </div>
        )}
        
        {/* Profile Section */}
        <div className="bg-white rounded-3xl shadow-2xl p-10 border border-gray-200 hover:shadow-[0_30px_80px_rgba(0,0,0,0.15)] transition-all duration-500 transform hover:scale-[1.01]">
          <div className="flex justify-between items-center mb-8">
            <h2 className="text-3xl font-bold text-gray-900 bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">📋 Profile Information</h2>
            {!editing && (
              <button
                onClick={() => setEditing(true)}
                className="px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-xl hover:from-blue-700 hover:to-blue-800 transition-all shadow-lg hover:shadow-xl font-bold transform hover:scale-105 active:scale-95"
              >
                ✏️ Edit Profile
              </button>
            )}
          </div>
          
          {editing ? (
            <div className="space-y-6">
              <div className="group">
                <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wider">
                  Full Name
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-5 py-4 border-2 border-gray-300 rounded-xl focus:ring-0 focus:border-blue-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white group-hover:shadow-lg"
                />
              </div>
              
              <div className="group">
                <label className="block text-sm font-bold text-gray-700 mb-3 tracking-wider">
                  Email Address
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full px-5 py-4 border-2 border-gray-300 rounded-xl focus:ring-0 focus:border-blue-600 transition-all duration-300 text-base font-medium bg-gray-50 hover:bg-white group-hover:shadow-lg"
                />
              </div>
              
              <div className="flex space-x-4 pt-4">
                <button
                  onClick={handleUpdate}
                  disabled={loading}
                  className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 text-white py-4 rounded-xl hover:from-blue-700 hover:to-blue-800 transition-all shadow-lg hover:shadow-xl font-bold disabled:opacity-50 transform hover:scale-105 active:scale-95"
                >
                  {loading ? '💾 Saving...' : '💾 Save Changes'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setEditing(false);
                    setFormData({ name: user.name, email: user.email });
                  }}
                  className="flex-1 bg-gradient-to-r from-gray-200 to-gray-300 text-gray-700 py-4 rounded-xl hover:from-gray-300 hover:to-gray-400 transition-all shadow-lg hover:shadow-xl font-bold transform hover:scale-105 active:scale-95"
                >
                  ✕ Cancel
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-5">
              <div
                onMouseEnter={(e) => e.currentTarget.style.transform = 'translateX(8px)'}
                onMouseLeave={(e) => e.currentTarget.style.transform = 'translateX(0)'}
                className="flex items-center space-x-4 p-6 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-2xl border-2 border-blue-200 hover:border-blue-400 transition-all duration-300 cursor-pointer shadow-md hover:shadow-lg"
              >
                <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-4 rounded-xl text-white shadow-lg">
                  <User className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm text-gray-600 font-medium">Name</p>
                  <p className="font-bold text-gray-900 text-lg">{user?.name}</p>
                </div>
              </div>
              
              <div
                onMouseEnter={(e) => e.currentTarget.style.transform = 'translateX(8px)'}
                onMouseLeave={(e) => e.currentTarget.style.transform = 'translateX(0)'}
                className="flex items-center space-x-4 p-6 bg-gradient-to-r from-purple-50 to-pink-50 rounded-2xl border-2 border-purple-200 hover:border-purple-400 transition-all duration-300 cursor-pointer shadow-md hover:shadow-lg"
              >
                <div className="bg-gradient-to-br from-purple-500 to-pink-600 p-4 rounded-xl text-white shadow-lg">
                  <Mail className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm text-gray-600 font-medium">Email</p>
                  <p className="font-bold text-gray-900 text-lg">{user?.email}</p>
                </div>
              </div>
              
              <div
                onMouseEnter={(e) => e.currentTarget.style.transform = 'translateX(8px)'}
                onMouseLeave={(e) => e.currentTarget.style.transform = 'translateX(0)'}
                className="flex items-center space-x-4 p-6 bg-gradient-to-r from-green-50 to-emerald-50 rounded-2xl border-2 border-green-200 hover:border-green-400 transition-all duration-300 cursor-pointer shadow-md hover:shadow-lg"
              >
                <div className="bg-gradient-to-br from-green-500 to-emerald-600 p-4 rounded-xl text-white shadow-lg">
                  <Shield className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm text-gray-600 font-medium">Role</p>
                  <p className="font-bold text-gray-900 text-lg">{user?.role || 'User'}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Main App Component
const App = () => {
  const [showSignup, setShowSignup] = useState(false);

  return (
    <AuthProvider>
      <AuthConsumer showSignup={showSignup} setShowSignup={setShowSignup} />
    </AuthProvider>
  );
};

const AuthConsumer = ({ showSignup, setShowSignup }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 p-4">
        {showSignup ? (
          <SignupForm onSwitchToLogin={() => setShowSignup(false)} />
        ) : (
          <LoginForm onSwitchToSignup={() => setShowSignup(true)} />
        )}
      </div>
    );
  }

  return <Dashboard />;
};

export default App;
  
