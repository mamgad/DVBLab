import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '../config';

const TransactionList = ({ userId }) => {
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [isSearching, setIsSearching] = useState(false);

  const fetchTransactions = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/api/transactions?user_id=${userId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setTransactions(data);
        setError(null);
      } else {
        setError('Failed to load transactions');
      }
    } catch (error) {
      setError('Failed to load transactions');
    } finally {
      setLoading(false);
    }
  };

  const searchTransactions = async () => {
    try {
      setIsSearching(true);
      // Call the vulnerable endpoint that's subject to SQL injection
      const response = await fetch(`${API_BASE_URL}/api/transactions/search?description=${encodeURIComponent(searchTerm)}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setTransactions(data);
        setError(null);
      } else {
        setError('Failed to search transactions');
      }
    } catch (error) {
      setError('Failed to search transactions');
    } finally {
      setIsSearching(false);
    }
  };

  useEffect(() => {
    fetchTransactions();
  }, [userId]);

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchTerm.trim()) {
      searchTransactions();
    } else {
      fetchTransactions();
    }
  };

  const handleReset = () => {
    setSearchTerm('');
    fetchTransactions();
  };

  if (loading && !isSearching) {
    return <div className="text-center py-4">Loading transactions...</div>;
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Transactions</h2>
      
      {/* Search Form */}
      <div className="mb-6 bg-white p-4 rounded-lg shadow-md">
        <form onSubmit={handleSearch} className="flex items-center space-x-4">
          <div className="flex-grow">
            <input
              type="text"
              placeholder="Search by description..."
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={isSearching}
          >
            {isSearching ? 'Searching...' : 'Search'}
          </button>
          {searchTerm && (
            <button
              type="button"
              onClick={handleReset}
              className="px-4 py-2 bg-gray-200 text-gray-800 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500"
            >
              Reset
            </button>
          )}
        </form>
      </div>

      {error && (
        <div className="text-red-600 text-center py-4 mb-6">{error}</div>
      )}

      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <table className="min-w-full">
          <thead>
            <tr className="bg-gray-50">
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {transactions.length === 0 ? (
              <tr>
                <td colSpan="5" className="px-6 py-4 text-center text-gray-500">
                  No transactions found.
                </td>
              </tr>
            ) : (
              transactions.map((transaction) => (
                <tr key={transaction.id}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {new Date(transaction.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {transaction.sender_id === parseInt(userId) ? 'Sent' : 'Received'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={transaction.sender_id === parseInt(userId) ? 'text-red-600' : 'text-green-600'}>
                      ${transaction.amount.toFixed(2)}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      transaction.status === 'completed' 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-yellow-100 text-yellow-800'
                    }`}>
                      {transaction.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                    {transaction.description || '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default TransactionList; 