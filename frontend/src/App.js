import React, { useState, useEffect } from 'react';
import { Bell, CreditCard, DollarSign, User, LogOut, Settings, Activity } from 'lucide-react';
import { Alert, AlertDescription } from './components/ui/alert';
import TransferForm from './components/TransferForm';
import TransactionList from './components/TransactionList';
import LoginPage from './components/LoginPage';

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
          <Alert className="m-4">
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
      <SidebarItem icon={Settings} label="Settings" page="settings" currentPage={currentPage} setCurrentPage={setCurrentPage} />
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

const Header = ({ user, onLogout }) => (
  <header className="bg-white shadow-md p-4">
    <div className="flex justify-between items-center">
      <div className="flex items-center">
        <h2 className="text-xl font-semibold">Welcome, {user.username}</h2>
      </div>
      <div className="flex items-center space-x-4">
        <Bell className="text-gray-600 cursor-pointer" />
        <div className="flex items-center cursor-pointer" onClick={onLogout}>
          <LogOut className="text-gray-600" />
          <span className="ml-2">Logout</span>
        </div>
      </div>
    </div>
  </header>
);

const Dashboard = ({ user, onTransferSuccess }) => (
  <div>
    <h2 className="text-2xl font-bold mb-6">Dashboard</h2>
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <DashboardCard title="Current Balance" value={`${user.balance.toFixed(2)}`} icon={DollarSign} />
      <DashboardCard title="Total Transactions" value="Loading..." icon={Activity} />
      <DashboardCard title="Notifications" value="3" icon={Bell} />
    </div>
    
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-xl font-semibold mb-4">Quick Transfer</h3>
      <TransferForm onSuccess={onTransferSuccess} />
    </div>
  </div>
);

const DashboardCard = ({ title, value, icon: Icon }) => (
  <div className="bg-white p-6 rounded-lg shadow-md">
    <div className="flex items-center justify-between mb-4">
      <h3 className="text-lg font-semibold text-gray-700">{title}</h3>
      <Icon className="text-blue-500" size={24} />
    </div>
    <p className="text-2xl font-bold text-gray-900">{value}</p>
  </div>
);

export default App; 