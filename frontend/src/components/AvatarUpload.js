import React, { useState } from 'react';
import { API_BASE_URL } from '../config';

// Uploads any file to /api/upload-avatar (no client- or server-side validation)
// and shows the resulting same-origin URL. An uploaded SVG/HTML file containing
// a <script> tag becomes stored XSS when opened from /uploads/<name>.
const AvatarUpload = () => {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleUpload = async (e) => {
    e.preventDefault();
    setError('');
    setResult(null);
    if (!file) {
      setError('Choose a file first');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch(`${API_BASE_URL}/api/upload-avatar`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: formData
      });
      const data = await response.json();
      if (response.ok) {
        setResult(`${API_BASE_URL}${data.url}`);
      } else {
        setError(data.error || 'Upload failed');
      }
    } catch (err) {
      setError('Upload failed');
    }
  };

  return (
    <div className="mt-6 border-t pt-6">
      <h3 className="text-lg font-medium text-gray-900 mb-4">Profile Picture</h3>
      <form onSubmit={handleUpload} className="flex items-center space-x-4">
        <input
          type="file"
          onChange={(e) => setFile(e.target.files[0])}
          className="text-sm"
        />
        <button
          type="submit"
          className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
        >
          Upload
        </button>
      </form>
      {error && <div className="mt-2 text-red-600 text-sm">{error}</div>}
      {result && (
        <div className="mt-2 text-sm">
          Uploaded:{' '}
          <a href={result} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline">
            {result}
          </a>
        </div>
      )}
    </div>
  );
};

export default AvatarUpload;
