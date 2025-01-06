# DVB Lab: Hands-on Web Security with Python & React
## A Practical Guide to Web Application Security

This repository contains a deliberately vulnerable banking application designed for learning secure code review and web application security. It serves as a practical learning environment where developers and security professionals can explore common security vulnerabilities, understand their impact, and learn how to fix them.

## Project Overview

### Purpose
The project aims to provide hands-on experience with:
- Identifying security vulnerabilities in real-world code
- Understanding attack vectors and exploitation techniques
- Learning secure coding practices
- Implementing security fixes
- Conducting thorough security assessments

### Technology Stack
- Backend: Python/Flask
- Frontend: React/TailwindCSS
- Database: SQLite
- Authentication: JWT
- Containerization: Docker

## Course Structure

0. Security Assessment Methodology
   - Threat modeling approaches
   - Source-to-sink analysis
   - Risk assessment techniques

1. SQL Injection Vulnerabilities
   - Understanding SQL Injection
   - Examples from our application
   - Prevention techniques

2. Authentication & Authorization
   - JWT implementation issues
   - Session management
   - Access control problems

3. Input Validation & Sanitization
   - Transaction amount validation
   - User input handling
   - Data type conversion issues

4. API Security
   - CORS configuration
   - Rate limiting
   - Error handling

5. Secure Coding Practices
   - Secure password handling
   - Proper logging
   - Transaction safety

## Installation Instructions

### Prerequisites
- Python 3.9 or higher
- Node.js 16 or higher
- Docker and Docker Compose (optional)
- Git

### Option 1: Docker Installation (Recommended)

#### Linux/macOS
```bash
# Clone the repository
git clone https://github.com/mamgad/vulnerable-bank.git
cd vulnerable-bank

# Start the application
docker-compose up --build
```

#### Windows
```powershell
# Clone the repository
git clone https://github.com/mamgad/vulnerable-bank.git
cd vulnerable-bank

# Start the application
docker-compose up --build
```

### Option 2: Manual Installation

#### Linux/macOS
```bash
# Clone the repository
git clone https://github.com/mamgad/vulnerable-bank.git
cd vulnerable-bank

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
python app.py &

# Frontend setup
cd ../frontend
npm install
npm start
```

#### Windows
```powershell
# Clone the repository
git clone https://github.com/mamgad/vulnerable-bank.git
cd vulnerable-bank

# Backend setup
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py

# In a new terminal
cd frontend
npm install
npm start
```

### Verifying Installation
1. Backend API should be running on http://localhost:5000
2. Frontend should be accessible at http://localhost:3000
3. Test using provided credentials:
   - Username: alice, Password: password123
   - Username: bob, Password: password123

## Project Structure
```
vulnerable-bank/
├── backend/
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth_routes.py
│   │   └── transaction_routes.py
│   ├── app.py
│   ├── models.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── App.js
│   │   └── index.js
│   ├── package.json
│   └── Dockerfile
└── docker-compose.yml
```

## Security Features to Explore
1. Authentication System
   - JWT implementation
   - Password hashing
   - Session management

2. Transaction System
   - Money transfers
   - Balance management
   - Transaction history

3. User Management
   - Registration
   - Profile management
   - Role-based access

## Known Vulnerabilities (for educational purposes)
1. SQL Injection in login functionality
2. Insecure JWT implementation
3. Missing input validation
4. IDOR vulnerabilities
5. Race conditions in transactions
6. Weak password policies

## Usage Guidelines
1. **Local Use Only**: This application contains intentional vulnerabilities. Never deploy it to a public server.
2. **Isolated Environment**: Run the application in an isolated development environment.
3. **Educational Purpose**: Use the vulnerabilities to learn, not for malicious purposes.
4. **Legal Disclaimer**: Users are responsible for how they use this application.

## Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request
4. Follow secure coding guidelines

## Support
- Create an issue for bugs or feature requests
- Join our community discussions
- Check the course modules for detailed guidance

## Additional Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Documentation](https://flask.palletsprojects.com/en/2.0.x/security/)
- [React Security Best Practices](https://reactjs.org/docs/security.html)
- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- OWASP Foundation
- Security research community
- Open source contributors

## Warning
This application contains intentional security vulnerabilities for educational purposes. DO NOT use any of this code in production environments. 