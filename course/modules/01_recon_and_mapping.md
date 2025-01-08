# Module 7: Application Reconnaissance & Attack Surface Mapping

## Learning Objectives
- Learn how to systematically explore a banking application
- Understand how to map application functionality and business logic
- Learn to identify different user roles and their capabilities
- Discover how to map the attack surface for both authenticated and unauthenticated users
- Understand the application's code structure and execution flow

## 1. Initial Application Exploration

### 1.1 Understanding the Application's Purpose
- This is a banking application that allows users to:
  - Manage their accounts
  - Perform money transfers
  - View transaction history
  - Update profile information
  - Manage account settings

### 1.2 User Roles and Access Levels
- Identify different types of users:
  - Unauthenticated users (public access)
  - Authenticated users (regular account holders)
  - Note any hints of administrative users

### 1.3 Feature Mapping
Create a checklist of features to explore:
- [ ] User Registration
- [ ] Login System
- [ ] Account Dashboard
- [ ] Money Transfer Functionality
- [ ] Transaction History
- [ ] Profile Management
- [ ] Account Settings
- [ ] Notification System

## 2. Understanding the Code Structure

### 2.1 Frontend Architecture (React)
```
frontend/
├── src/
│   ├── components/     # React components
│   ├── config.js       # Configuration settings
│   └── App.js          # Main application component
```

Key areas to examine:
1. Component Structure
   - How are components organized?
   - What is the relationship between components?
   - How is state managed?

2. API Integration
   - How does the frontend communicate with the backend?
   - What endpoints are being called?
   - How is authentication handled in requests?

### 2.2 Backend Architecture (Python Flask)
```
backend/
├── routes/            # API endpoints
├── models/            # Database models
└── app.py            # Main application file
```

Key areas to examine:
1. Route Structure
   - What endpoints are available?
   - Which routes require authentication?
   - What HTTP methods are supported?

2. Data Flow
   - How is data processed?
   - Where is business logic implemented?
   - How is data stored and retrieved?

## 3. Mapping the Attack Surface

### 3.1 Unauthenticated Attack Surface
Start by identifying publicly accessible functionality:

1. Authentication Endpoints
   - Login endpoint
   - Registration endpoint
   - Password reset (if available)

2. Public Information
   - Error messages
   - API documentation (if available)
   - Version information
   - Response headers

### 3.2 Authenticated Attack Surface

1. User Profile Operations
   - Profile viewing
   - Profile updating
   - Password changes

2. Financial Operations
   - Money transfers
   - Balance checking
   - Transaction history

3. Account Settings
   - Notification preferences
   - Security settings
   - Account management

### 3.3 API Endpoint Mapping
Create a comprehensive list of endpoints:
```
POST /api/login
POST /api/register
GET  /api/me
POST /api/transfer
GET  /api/transactions
PUT  /api/profile
```

## 4. Understanding Business Logic

### 4.1 Core Business Flows
1. Money Transfer Process
   - How is a transfer initiated?
   - What validations are performed?
   - How is the transfer executed?

2. Account Management
   - How is user data stored?
   - What information can users modify?
   - How are settings persisted?

### 4.2 Security Controls
Identify existing security measures:
1. Authentication
   - Token-based authentication
   - Session management
   - Login requirements

2. Authorization
   - Role-based access control
   - Permission checks
   - API endpoint protection

## 5. Testing Methodology

### 5.1 Systematic Approach
1. Create a testing plan:
   - Map all features
   - Document normal flows
   - Identify edge cases
   - List test scenarios

2. Testing Priorities:
   - Critical functionality first
   - Money-related features
   - User data protection
   - Authentication mechanisms

### 5.2 Documentation
Keep detailed records of:
- Application structure
- API endpoints
- Business logic flows
- Test cases and results

## Exercises

1. Application Mapping
   - Create a complete map of all application features
   - Document all API endpoints
   - Identify different user roles and their capabilities

2. Business Logic Analysis
   - Draw a flowchart of the money transfer process
   - Document all steps in user registration and authentication
   - Map out the relationship between different components

3. Attack Surface Documentation
   - Create a list of all entry points for unauthenticated users
   - Document all authenticated user functionality
   - Identify potential security boundaries between features

## Conclusion
Understanding the application's structure, business logic, and attack surface is crucial before beginning any security testing. This methodical approach helps ensure thorough coverage and better identification of potential security issues.

Remember:
- Start with understanding the application's purpose and features
- Map out the code structure and data flow
- Document all entry points and user roles
- Understand the business logic thoroughly
- Create a systematic testing approach

## Additional Resources
- OWASP Web Security Testing Guide
- Web Application Hacker's Handbook
- API Security Testing Guidelines 