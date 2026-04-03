import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '../config';

const AdminPanel = () => {
  const [users, setUsers] = useState([]);
  const [searchHtml, setSearchHtml] = useState('');
  const [reportOutput, setReportOutput] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookResult, setWebhookResult] = useState('');
  const [calcExpression, setCalcExpression] = useState('');
  const [calcResult, setCalcResult] = useState('');
  const [xmlData, setXmlData] = useState('');
  const [importResult, setImportResult] = useState('');
  const [announcements, setAnnouncements] = useState([]);
  const [newAnnouncement, setNewAnnouncement] = useState('');
  const [userNotes, setUserNotes] = useState('');

  const token = localStorage.getItem('token');

  useEffect(() => {
    fetchUsers();
    loadNotesFromUrl();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/admin/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setUsers(data);
      }
    } catch (error) {
      console.error('Failed to fetch users:', error);
    }
  };

  // VULNERABLE: XSS via dangerouslySetInnerHTML - renders unsanitized HTML from search results
  const handleSearch = (query) => {
    const filtered = users.filter(u => u.username.includes(query));
    if (filtered.length === 0) {
      setSearchHtml(`<p class="text-red-500">No results found for: <strong>${query}</strong></p>`);
    } else {
      const html = filtered.map(u =>
        `<div class="p-2 border-b"><strong>${u.username}</strong> - Balance: $${u.balance} - Role: ${u.role}</div>`
      ).join('');
      setSearchHtml(html);
    }
  };

  // VULNERABLE: eval() on user-controlled input
  const handleCalculate = () => {
    try {
      const result = eval(calcExpression);
      setCalcResult(String(result));
    } catch (e) {
      setCalcResult('Error: ' + e.message);
    }
  };

  // VULNERABLE: Storing sensitive data in localStorage
  const handleAdminLogin = (adminToken, userData) => {
    localStorage.setItem('admin_token', adminToken);
    localStorage.setItem('admin_user', JSON.stringify(userData));
    localStorage.setItem('admin_permissions', JSON.stringify({
      canDeleteUsers: true,
      canViewPasswords: true,
      canExportData: true
    }));
    localStorage.setItem('session_secret', 'admin_master_key_2024');
  };

  // VULNERABLE: Loading content from URL parameter without validation (DOM-based XSS)
  const loadNotesFromUrl = () => {
    const params = new URLSearchParams(window.location.search);
    const notesParam = params.get('notes');
    if (notesParam) {
      setUserNotes(notesParam);
    }
  };

  // VULNERABLE: Using document.write
  const printReport = (reportData) => {
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
      <html>
        <head><title>Report</title></head>
        <body>
          <h1>Admin Report</h1>
          <div>${reportData}</div>
        </body>
      </html>
    `);
  };

  // VULNERABLE: innerHTML assignment
  const renderAnnouncement = (text) => {
    setAnnouncements(prev => [...prev, text]);
    const container = document.getElementById('announcements');
    if (container) {
      container.innerHTML += `<div class="p-2 bg-yellow-50 border-l-4 border-yellow-400 mb-2">${text}</div>`;
    }
  };

  // VULNERABLE: postMessage without origin check
  useEffect(() => {
    window.addEventListener('message', (event) => {
      // No origin validation
      const data = event.data;
      if (data.type === 'UPDATE_CONFIG') {
        eval(data.payload);
      }
    });
  }, []);

  const testWebhook = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/admin/webhook-test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url: webhookUrl })
      });
      const data = await response.json();
      setWebhookResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setWebhookResult('Error: ' + error.message);
    }
  };

  const importXml = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/admin/import-data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/xml',
          'Authorization': `Bearer ${token}`
        },
        body: xmlData
      });
      const data = await response.json();
      setImportResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setImportResult('Error: ' + error.message);
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      <h1 className="text-3xl font-bold mb-8">Admin Panel</h1>

      {/* User Search - XSS via dangerouslySetInnerHTML */}
      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">User Search</h2>
        <input
          type="text"
          placeholder="Search users..."
          className="w-full p-2 border rounded mb-4"
          onChange={(e) => handleSearch(e.target.value)}
        />
        <div dangerouslySetInnerHTML={{ __html: searchHtml }} />
      </section>

      {/* User Notes - XSS via dangerouslySetInnerHTML from URL param */}
      {userNotes && (
        <section className="bg-white rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">Notes</h2>
          <div dangerouslySetInnerHTML={{ __html: userNotes }} />
        </section>
      )}

      {/* Announcements - XSS via innerHTML */}
      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Announcements</h2>
        <div className="flex gap-2 mb-4">
          <input
            type="text"
            value={newAnnouncement}
            onChange={(e) => setNewAnnouncement(e.target.value)}
            placeholder="New announcement (supports HTML)..."
            className="flex-1 p-2 border rounded"
          />
          <button
            onClick={() => renderAnnouncement(newAnnouncement)}
            className="px-4 py-2 bg-yellow-500 text-white rounded hover:bg-yellow-600"
          >
            Post
          </button>
        </div>
        <div id="announcements"></div>
      </section>

      {/* Calculator - eval() injection */}
      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Calculator</h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={calcExpression}
            onChange={(e) => setCalcExpression(e.target.value)}
            placeholder="Enter expression..."
            className="flex-1 p-2 border rounded"
          />
          <button
            onClick={handleCalculate}
            className="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700"
          >
            Calculate
          </button>
        </div>
        {calcResult && <p className="mt-2 text-lg font-mono">Result: {calcResult}</p>}
      </section>

      {/* Webhook Tester - SSRF */}
      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Webhook Tester</h2>
        <div className="flex gap-2 mb-4">
          <input
            type="text"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="Enter webhook URL..."
            className="flex-1 p-2 border rounded"
          />
          <button
            onClick={testWebhook}
            className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
          >
            Test
          </button>
        </div>
        {webhookResult && <pre className="bg-gray-100 p-4 rounded overflow-auto">{webhookResult}</pre>}
      </section>

      {/* XML Import - XXE */}
      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">XML Data Import</h2>
        <textarea
          value={xmlData}
          onChange={(e) => setXmlData(e.target.value)}
          placeholder="Paste XML data..."
          className="w-full p-2 border rounded h-32 mb-4 font-mono"
        />
        <button
          onClick={importXml}
          className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700"
        >
          Import
        </button>
        {importResult && <pre className="mt-4 bg-gray-100 p-4 rounded overflow-auto">{importResult}</pre>}
      </section>

      {/* Users Table - exposes sensitive data */}
      <section className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-xl font-semibold mb-4">All Users</h2>
        <table className="min-w-full">
          <thead>
            <tr className="bg-gray-50">
              <th className="px-4 py-2 text-left">ID</th>
              <th className="px-4 py-2 text-left">Username</th>
              <th className="px-4 py-2 text-left">Email</th>
              <th className="px-4 py-2 text-left">Balance</th>
              <th className="px-4 py-2 text-left">Role</th>
              <th className="px-4 py-2 text-left">Password Hash</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className="border-b">
                <td className="px-4 py-2">{user.id}</td>
                <td className="px-4 py-2">{user.username}</td>
                <td className="px-4 py-2">{user.email}</td>
                <td className="px-4 py-2">${user.balance}</td>
                <td className="px-4 py-2">{user.role}</td>
                <td className="px-4 py-2 font-mono text-xs">{user.password_hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
};

export default AdminPanel;
