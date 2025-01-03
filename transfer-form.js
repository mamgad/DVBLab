import React, { useState } from 'react';

const TransferForm = ({ onSuccess }) => {
  const [receiverId, setReceiverId] = useState('');
  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    try {
      const response = await fetch('http://localhost:5000/api/transfer', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          receiver_id: parseInt(receiverId),
          amount: parseFloat(amount),
          description
        })
      });

      const data = await response.json();
      
      if (response.ok) {
        setReceiverId('');
        setAmount('');
        setDescription('');
        onSuccess();
      } else {
        setError(data.error || 'Transfer failed');
      }
    } catch (error) {
      setError('Transfer failed');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-gray-700 mb-2">Receiver ID</label>
          <input
            type="number"
            className="w-full p-2 border rounded focus:outline-none focus:border-blue-500"
            value={receiverId}
            onChange={(e) => setReceiverId(e.target.value)}
            required
          />
        </div>
        <div>
          <label className="block text-gray-700 mb-2">Amount</label>
          <input
            type="number"
            step="0.01"
            className="w-full p-2 border rounded focus:outline-none focus:border-blue-500"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            required
          />
        </div>
      </div>
      <div className="mt-4">
        <label className="block text-gray-700 mb-2">Description</label>
        <input
          type="text"
          className="w-full p-2 border rounded focus:outline-none focus:border-blue-500"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      {error && (
        <div className="mt-4 text-red-600">{error}</div>
      )}
      <button
        type="submit"
        className="mt-6 bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700"
      >
        Transfer
      </button>
    </form>
  );
};

export default TransferForm;