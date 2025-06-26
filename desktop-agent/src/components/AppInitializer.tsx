import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Lock, Unlock, Shield, AlertCircle } from 'lucide-react';

// Mock Tauri API for demonstration
// In the actual implementation, this would use @tauri-apps/api/tauri
const mockTauri = {
  invoke: async (command: string, args?: any) => {
    console.log(`Tauri command: ${command}`, args);
    
    // Simulate API responses
    switch (command) {
      case 'check_initialization_status':
        return localStorage.getItem('app_initialized') === 'true';
      
      case 'initialize_app':
        if (args.password && args.password.length >= 12) {
          localStorage.setItem('app_initialized', 'true');
          return 'Application initialized successfully';
        }
        throw new Error('Invalid password');
      
      case 'unlock_app':
        if (args.password === localStorage.getItem('mock_password')) {
          return;
        }
        throw new Error('Invalid password');
      
      case 'lock_app':
        return;
      
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  }
};

export default function AppInitializer() {
  const [isInitialized, setIsInitialized] = useState<boolean | null>(null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [isLocked, setIsLocked] = useState(false);

  useEffect(() => {
    checkInitializationStatus();
  }, []);

  const checkInitializationStatus = async () => {
    try {
      const status = await mockTauri.invoke('check_initialization_status');
      setIsInitialized(status as boolean);
      setIsLocked(!(status as boolean));
    } catch (err) {
      console.error('Failed to check initialization status:', err);
      setIsInitialized(false);
    }
  };

  const handleInitialize = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password.length < 12) {
      setError('Password must be at least 12 characters long');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Check password complexity
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
      setError('Password must contain uppercase, lowercase, numbers, and special characters');
      return;
    }

    setIsLoading(true);
    try {
      await mockTauri.invoke('initialize_app', { password });
      localStorage.setItem('mock_password', password); // For demo only
      setIsInitialized(true);
      setIsLocked(false);
      setPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setError(err.message || 'Failed to initialize application');
    } finally {
      setIsLoading(false);
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await mockTauri.invoke('unlock_app', { password });
      setIsLocked(false);
      setPassword('');
    } catch (err) {
      setError('Invalid password');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLock = async () => {
    try {
      await mockTauri.invoke('lock_app');
      setIsLocked(true);
    } catch (err: any) {
      setError(err.message || 'Failed to lock application');
    }
  };

  if (isInitialized === null) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  if (!isInitialized) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <Shield className="mx-auto h-12 w-12 text-blue-500" />
            <h2 className="mt-6 text-3xl font-extrabold text-white">
              Welcome to Desktop Agent
            </h2>
            <p className="mt-2 text-sm text-gray-400">
              Create a master password to secure your data
            </p>
          </div>
          
          <form className="mt-8 space-y-6" onSubmit={handleInitialize}>
            <div className="space-y-4">
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                  Master Password
                </label>
                <div className="mt-1 relative">
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="appearance-none block w-full px-3 py-2 pr-10 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 bg-gray-800 text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Enter a strong password"
                  />
                  <button
                    type="button"
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeOff className="h-5 w-5 text-gray-400" />
                    ) : (
                      <Eye className="h-5 w-5 text-gray-400" />
                    )}
                  </button>
                </div>
              </div>
              
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-300">
                  Confirm Password
                </label>
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="appearance-none block w-full px-3 py-2 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 bg-gray-800 text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Confirm your password"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center space-x-2 text-red-400 text-sm">
                <AlertCircle className="h-4 w-4" />
                <span>{error}</span>
              </div>
            )}

            <div className="space-y-3">
              <div className="bg-gray-800 p-4 rounded-md">
                <h3 className="text-sm font-medium text-gray-300 mb-2">Password Requirements:</h3>
                <ul className="text-xs text-gray-400 space-y-1">
                  <li>• At least 12 characters long</li>
                  <li>• Mix of uppercase and lowercase letters</li>
                  <li>• Include numbers and special characters</li>
                  <li>• This password cannot be recovered if lost</li>
                </ul>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Initializing...' : 'Initialize Application'}
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  if (isLocked) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <Lock className="mx-auto h-12 w-12 text-blue-500" />
            <h2 className="mt-6 text-3xl font-extrabold text-white">
              Application Locked
            </h2>
            <p className="mt-2 text-sm text-gray-400">
              Enter your master password to unlock
            </p>
          </div>
          
          <form className="mt-8 space-y-6" onSubmit={handleUnlock}>
            <div>
              <label htmlFor="unlock-password" className="block text-sm font-medium text-gray-300">
                Master Password
              </label>
              <div className="mt-1 relative">
                <input
                  id="unlock-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="appearance-none block w-full px-3 py-2 pr-10 border border-gray-600 rounded-md shadow-sm placeholder-gray-400 bg-gray-800 text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-gray-400" />
                  ) : (
                    <Eye className="h-5 w-5 text-gray-400" />
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center space-x-2 text-red-400 text-sm">
                <AlertCircle className="h-4 w-4" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Unlocking...' : 'Unlock Application'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-500" />
              <h1 className="text-xl font-semibold text-white">Desktop Agent</h1>
            </div>
            <button
              onClick={handleLock}
              className="flex items-center space-x-2 px-4 py-2 border border-gray-600 rounded-md text-sm font-medium text-gray-300 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              <Lock className="h-4 w-4" />
              <span>Lock Application</span>
            </button>
          </div>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Unlock className="h-6 w-6 text-green-500" />
            <h2 className="text-lg font-medium text-white">Application Unlocked</h2>
          </div>
          <p className="text-gray-400">
            Your application is now unlocked and ready to use. All data is encrypted and secure.
          </p>
          <div className="mt-4 p-4 bg-gray-700 rounded text-sm text-gray-300">
            <p className="font-semibold mb-2">Note: This is a demonstration component</p>
            <p>In the actual Tauri application, this would communicate with the Rust backend using @tauri-apps/api. The mock implementation shows the intended UI/UX flow.</p>
          </div>
        </div>
      </div>
    </div>
  );
}