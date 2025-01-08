import React, { useState } from 'react';
import { API_BASE_URL } from '../config';

const PasswordUpdate = () => {
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem('token');
      const userId = JSON.parse(atob(token.split('.')[1])).user_id;
      
      const response = await fetch(`${API_BASE_URL}/api/update-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          user_id: userId,
          new_password: newPassword
        })
      });

      const data = await response.json();
      setMessage(data.message || data.error);
      if (response.ok) setNewPassword('');
    } catch (error) {
      setMessage('Failed to update password');
    }
  };

  return (
    <div className="bg-white p-6 rounded shadow">
      <h2 className="text-xl mb-4">Update Password</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="Enter new password"
          className="border p-2 mr-2"
          required
        />
        <button type="submit" className="bg-blue-500 text-white p-2 rounded">
          Update Password
        </button>
      </form>
      {message && <p className="mt-4">{message}</p>}
    </div>
  );
};

export default PasswordUpdate; 