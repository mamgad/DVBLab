# Module 6: API Security

## Understanding API Security
Modern web applications heavily rely on APIs (Application Programming Interfaces) to facilitate communication between different components and services. While APIs enable powerful functionality and integration capabilities, they also introduce unique security challenges that must be carefully addressed. This module explores common API vulnerabilities and teaches you how to identify, exploit, and fix them.

### What is API Security?
API security is the practice of protecting APIs from attacks that could compromise their:
- Confidentiality (data privacy)
- Integrity (data accuracy)
- Availability (service uptime)
- Authentication (user identity)
- Authorization (user permissions)

Each of these aspects requires specific security controls and careful implementation to ensure robust API protection.

### Common API Security Concerns
Understanding the various ways APIs can be compromised is essential for building secure applications:

1. **Authentication Issues**
   - Missing or weak authentication mechanisms
   - Token exposure through insecure transmission
   - Credential leakage in logs or errors
   - Improper session management

2. **Authorization Flaws**
   - Missing or insufficient access controls
   - Broken object-level authorization (BOLA)
   - Excessive permissions granted to clients
   - Role confusion and privilege escalation

3. **Data Exposure**
   - Sensitive data included in responses
   - Excessive data exposure in API responses
   - Unencrypted data transmission
   - Debug information in error messages

4. **Resource Management**
   - Missing or ineffective rate limiting
   - Absence of resource quotas
   - Denial of Service vulnerabilities
   - Uncontrolled resource consumption

### API Attack Vectors
Attackers can exploit APIs through various methods. Understanding these attack vectors is crucial for proper defense:

1. **Parameter Tampering**
   - Manipulation of query parameters
   - Request body modification
   - Header injection attacks
   - Cookie manipulation

2. **API Abuse**
   - Systematic endpoint enumeration
   - API version manipulation
   - HTTP method spoofing
   - Content-type abuse

3. **Infrastructure Attacks**
   - Server-Side Request Forgery (SSRF)
   - XML External Entity (XXE) injection
   - API gateway bypass attempts
   - Service discovery exploitation

## DVBank API Vulnerabilities
Let's examine real API security vulnerabilities present in the DVBank application. These examples demonstrate common security issues found in real-world applications.

### 1. CORS Misconfiguration
**Location**: `backend/app.py`
```python
from flask_cors import CORS

# Overly permissive CORS
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "supports_credentials": True
    }
})
```

**Impact**:
- Cross-origin attacks become possible
- Credentials can be exposed to malicious sites
- CSRF vulnerabilities may be introduced
- Sensitive data theft potential increases

**Exploitation**:
```javascript
// Malicious site can make authenticated requests
fetch('https://dvbank.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({
        to_account: 'attacker',
        amount: 1000
    })
})
```

### 2. Missing Rate Limiting
**Location**: `backend/routes/auth_routes.py`
```python
@app.route('/api/login', methods=['POST'])
def login():
    # No rate limiting
    # No brute force protection
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = authenticate(username, password)
```

**Impact**:
- Brute force attacks on authentication
- Potential DoS through resource exhaustion
- Account enumeration becomes possible
- Server resources can be depleted

**Exploitation**:
```python
import requests

# Brute force attack
for password in passwords:
    response = requests.post('/api/login', json={
        'username': 'admin',
        'password': password
    })
    if response.status_code == 200:
        print(f"Found password: {password}")
```

### 3. Excessive Data Exposure
**Location**: `backend/routes/user_routes.py`
```python
@app.route('/api/users/<user_id>')
@login_required
def get_user(user_id):
    user = User.query.get(user_id)
    # Returns all user data including sensitive fields
    return jsonify(user.to_dict())
```

**Impact**:
- Exposure of Personally Identifiable Information (PII)
- Sensitive data leakage through API responses
- Privacy violations of user data
- Potential regulatory compliance issues

**Exploitation**:
```python
# Fetch user data to extract sensitive info
response = requests.get('/api/users/1')
user_data = response.json()

# Access sensitive fields
print(f"SSN: {user_data['ssn']}")
print(f"DOB: {user_data['date_of_birth']}")
```

## Prevention Methods
Implementing proper API security controls is essential for protecting your application. Here are secure implementation examples:

### 1. Secure CORS Configuration
```python
from flask_cors import CORS

# Proper CORS setup
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://dvbank.com"],
        "supports_credentials": True,
        "methods": ["GET", "POST"],
        "allow_headers": ["Authorization", "Content-Type"],
        "expose_headers": ["X-Total-Count"],
        "max_age": 3600
    }
})
```

### 2. API Rate Limiting
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Track failed attempts
    if not user:
        track_failed_login(username, get_remote_address())
        if get_failed_attempts(username) > 5:
            block_ip(get_remote_address())
        return jsonify({"error": "Invalid credentials"}), 401
```

### 3. Data Filtering
```python
class UserDTO:
    def __init__(self, user):
        self.id = user.id
        self.username = user.username
        self.email = user.email
        # Exclude sensitive fields
        
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email
        }

@app.route('/api/users/<user_id>')
@login_required
def get_user(user_id):
    user = User.query.get(user_id)
    # Return filtered data
    return jsonify(UserDTO(user).to_dict())
```

## Practice Exercises
These exercises will help you understand and identify API security vulnerabilities:

1. **CORS Security**
   - Configure proper origin restrictions
   - Test CORS policy effectiveness
   - Implement preflight request handling
   - Secure credential transmission

2. **Rate Limiting**
   - Implement request rate limits
   - Add IP-based blocking
   - Track and manage failed attempts
   - Configure retry-after headers

3. **Data Protection**
   - Create Data Transfer Objects (DTOs)
   - Implement response filtering
   - Add sensitive data masking
   - Define field-level security policies

## Additional Resources
To deepen your understanding of API security:

1. [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
2. [REST Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
3. [API Security Best Practices](https://www.pingidentity.com/en/company/blog/posts/2020/api-security-best-practices.html)

### Related Tools
1. [Postman](https://www.postman.com/) - API testing and security assessment
2. [OWASP ZAP](https://www.zaproxy.org/) - API security testing
3. [Burp Suite](https://portswigger.net/burp) - Web API security testing
4. [API Security Scanner](https://apisec.ai/) - Automated API security testing

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 