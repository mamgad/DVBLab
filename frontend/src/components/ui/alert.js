import React from 'react';

export const Alert = ({ className, children }) => (
  <div className={`bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative ${className}`} role="alert">
    {children}
  </div>
);

export const AlertDescription = ({ children }) => (
  <span className="block sm:inline">{children}</span>
); 