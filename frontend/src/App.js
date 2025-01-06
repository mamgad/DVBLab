import React, { useState, useEffect } from 'react';
import { Bell, CreditCard, DollarSign, User, LogOut, Settings as SettingsIcon, Activity } from 'lucide-react';
import { Alert, AlertDescription } from './components/ui/alert';
import TransferForm from './components/TransferForm';
import TransactionList from './components/TransactionList';
import LoginPage from './components/LoginPage';
import './index.css';

const App = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [user, setUser] = useState(null);
  const [showAlert, setShowAlert] = useState(false);
  const [alertMessage, setAlertMessage] = useState('');

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      fetchUserData();
    }
  }, []);

  const fetchUserData = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/me', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      } else {
        localStorage.removeItem('token');
      }
    } catch (error) {
      console.error('Failed to fetch user data:', error);
    }
  };

  const handleLogin = async (username, password) => {
    try {
      const response = await fetch('http://localhost:5000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      if (response.ok) {
        localStorage.setItem('token', data.token);
        setUser(data.user);
        setCurrentPage('dashboard');
      } else {
        showAlertMessage(data.error || 'Login failed');
      }
    } catch (error) {
      showAlertMessage('Login failed');
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('http://localhost:5000/api/logout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
    } finally {
      localStorage.removeItem('token');
      setUser(null);
    }
  };

  const showAlertMessage = (message) => {
    setAlertMessage(message);
    setShowAlert(true);
    setTimeout(() => setShowAlert(false), 3000);
  };

  if (!user) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <div className="flex min-h-screen bg-gray-100">
      <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />
      <div className="flex-1">
        <Header user={user} onLogout={handleLogout} />
        
        {showAlert && (
          <Alert className={`m-4 ${
            alertMessage.toLowerCase().includes('success') ? 'bg-green-50 border-green-500 text-green-800' : 'bg-red-50 border-red-500 text-red-800'
          }`}>
            <AlertDescription>{alertMessage}</AlertDescription>
          </Alert>
        )}
        
        <main className="p-6">
          {currentPage === 'dashboard' && (
            <Dashboard 
              user={user} 
              onTransferSuccess={() => {
                fetchUserData();
                showAlertMessage('Transfer successful');
              }} 
            />
          )}
          {currentPage === 'transactions' && (
            <TransactionList userId={user.id} />
          )}
          {currentPage === 'profile' && (
            <Profile user={user} />
          )}
          {currentPage === 'settings' && (
            <Settings />
          )}
        </main>
      </div>
    </div>
  );
};

const Sidebar = ({ currentPage, setCurrentPage }) => (
  <div className="w-64 bg-gray-800 min-h-screen p-4">
    <div className="mb-8">
      <h1 className="text-white text-2xl font-bold">VulnerableBank</h1>
    </div>
    <nav>
      <SidebarItem icon={Activity} label="Dashboard" page="dashboard" currentPage={currentPage} setCurrentPage={setCurrentPage} />
      <SidebarItem icon={CreditCard} label="Transactions" page="transactions" currentPage={currentPage} setCurrentPage={setCurrentPage} />
      <SidebarItem icon={User} label="Profile" page="profile" currentPage={currentPage} setCurrentPage={setCurrentPage} />
      <SidebarItem icon={SettingsIcon} label="Settings" page="settings" currentPage={currentPage} setCurrentPage={setCurrentPage} />
    </nav>
  </div>
);

const SidebarItem = ({ icon: Icon, label, page, currentPage, setCurrentPage }) => (
  <div
    className={`flex items-center p-3 rounded-lg cursor-pointer mb-2 ${
      currentPage === page ? 'bg-blue-600' : 'hover:bg-gray-700'
    }`}
    onClick={() => setCurrentPage(page)}
  >
    <Icon size={20} className="text-white" />
    <span className="ml-3 text-white">{label}</span>
  </div>
);

const Header = ({ user, onLogout }) => {
  const [notifications, setNotifications] = useState([]);
  const [showNotifications, setShowNotifications] = useState(false);

  useEffect(() => {
    fetchNotifications();
  }, []);

  const fetchNotifications = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/transactions', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (response.ok) {
        const transactions = await response.json();
        // Get recent transactions (last 24 hours)
        const recentTransactions = transactions.filter(t => {
          const transactionDate = new Date(t.created_at);
          const yesterday = new Date();
          yesterday.setDate(yesterday.getDate() - 1);
          return transactionDate > yesterday;
        });
        setNotifications(recentTransactions);
      }
    } catch (error) {
      console.error('Failed to fetch notifications:', error);
    }
  };

  return (
    <header className="bg-white shadow-md p-4">
      <div className="flex justify-between items-center">
        <div className="flex items-center">
          <h2 className="text-xl font-semibold">Welcome, {user.username}</h2>
          <span className="ml-2 text-gray-500">(ID: {user.id})</span>
        </div>
        <div className="flex items-center space-x-4">
          <div className="relative">
            <div className="relative" onClick={() => setShowNotifications(!showNotifications)}>
              <Bell className="text-gray-600 cursor-pointer" />
              {notifications.length > 0 && (
                <span className="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                  {notifications.length}
                </span>
              )}
            </div>
            
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-lg z-50">
                <div className="p-4">
                  <h3 className="text-lg font-semibold mb-2">Recent Transactions</h3>
                  <div className="space-y-2">
                    {notifications.map(transaction => (
                      <div key={transaction.id} className="p-2 hover:bg-gray-50 rounded">
                        <p className="text-sm">
                          {transaction.sender_id === user.id ? 'Sent' : 'Received'} ${transaction.amount}
                        </p>
                        <p className="text-xs text-gray-500">
                          {new Date(transaction.created_at).toLocaleString()}
                        </p>
                      </div>
                    ))}
                    {notifications.length === 0 && (
                      <p className="text-sm text-gray-500">No recent transactions</p>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
          <div className="flex items-center cursor-pointer" onClick={onLogout}>
            <LogOut className="text-gray-600" />
            <span className="ml-2">Logout</span>
          </div>
        </div>
      </div>
    </header>
  );
};

const Dashboard = ({ user, onTransferSuccess }) => {
  const [transactionCount, setTransactionCount] = useState(0);
  const [unreadNotifications, setUnreadNotifications] = useState(0);

  useEffect(() => {
    const fetchTransactionCount = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/transactions', {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        });
        if (response.ok) {
          const transactions = await response.json();
          setTransactionCount(transactions.length);
          // Count unread notifications (transactions in the last 24 hours)
          const recentTransactions = transactions.filter(t => {
            const transactionDate = new Date(t.created_at);
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            return transactionDate > yesterday;
          });
          setUnreadNotifications(recentTransactions.length);
        }
      } catch (error) {
        console.error('Failed to fetch transactions:', error);
      }
    };

    fetchTransactionCount();
  }, []);

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <DashboardCard title="User ID" value={user.id} icon={User} />
        <DashboardCard title="Current Balance" value={`$${user.balance.toFixed(2)}`} icon={DollarSign} />
        <DashboardCard title="Total Transactions" value={transactionCount} icon={Activity} />
        <DashboardCard title="Notifications" value={unreadNotifications} icon={Bell} />
      </div>
      
      <div className="bg-white rounded-lg shadow-md p-6">
        <h3 className="text-xl font-semibold mb-4">Quick Transfer</h3>
        <TransferForm onSuccess={onTransferSuccess} />
      </div>
    </div>
  );
};

const DashboardCard = ({ title, value, icon: Icon }) => (
  <div className="bg-white p-6 rounded-lg shadow-md">
    <div className="flex items-center justify-between mb-4">
      <h3 className="text-lg font-semibold text-gray-700">{title}</h3>
      <Icon className="text-blue-500" size={24} />
    </div>
    <p className="text-2xl font-bold text-gray-900">{value}</p>
  </div>
);

const Profile = ({ user }) => {
  const [profile, setProfile] = useState({
    fullName: '',
    email: '',
    phone: '',
    address: ''
  });
  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/profile', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setProfile(data);
      }
    } catch (error) {
      console.error('Failed to fetch profile:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(profile)
      });

      if (response.ok) {
        setIsEditing(false);
        // Refresh profile data
        fetchProfile();
      }
    } catch (error) {
      console.error('Failed to update profile:', error);
    }
  };

  if (isLoading) {
    return <div className="text-center py-4">Loading profile...</div>;
  }

  return (
    <div className="max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold mb-6">Profile</h2>
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-semibold">Personal Information</h3>
          <button
            onClick={() => setIsEditing(!isEditing)}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
          >
            {isEditing ? 'Cancel' : 'Edit'}
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Full Name</label>
            <input
              type="text"
              value={profile.fullName}
              onChange={(e) => setProfile({ ...profile, fullName: e.target.value })}
              disabled={!isEditing}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Email</label>
            <input
              type="email"
              value={profile.email}
              onChange={(e) => setProfile({ ...profile, email: e.target.value })}
              disabled={!isEditing}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Phone</label>
            <input
              type="tel"
              value={profile.phone}
              onChange={(e) => setProfile({ ...profile, phone: e.target.value })}
              disabled={!isEditing}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Address</label>
            <textarea
              value={profile.address}
              onChange={(e) => setProfile({ ...profile, address: e.target.value })}
              disabled={!isEditing}
              rows={3}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          {isEditing && (
            <div className="flex justify-end">
              <button
                onClick={handleSave}
                className="px-4 py-2 text-sm font-medium text-white bg-green-600 rounded-md hover:bg-green-700"
              >
                Save Changes
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const Settings = () => {
  const [settings, setSettings] = useState({
    emailNotifications: true,
    twoFactorAuth: false,
    language: 'en',
    theme: 'light'
  });

  const handleChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold mb-6">Settings</h2>
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="space-y-6">
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Notifications</h3>
            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.emailNotifications}
                onChange={(e) => handleChange('emailNotifications', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <label className="ml-2 block text-sm text-gray-900">
                Email Notifications
              </label>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Security</h3>
            <div className="flex items-center">
              <input
                type="checkbox"
                checked={settings.twoFactorAuth}
                onChange={(e) => handleChange('twoFactorAuth', e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <label className="ml-2 block text-sm text-gray-900">
                Two-Factor Authentication
              </label>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Preferences</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Language</label>
                <select
                  value={settings.language}
                  onChange={(e) => handleChange('language', e.target.value)}
                  className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
                >
                  <option value="en">English</option>
                  <option value="es">Spanish</option>
                  <option value="fr">French</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Theme</label>
                <select
                  value={settings.theme}
                  onChange={(e) => handleChange('theme', e.target.value)}
                  className="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
                >
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                  <option value="system">System</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default App; 