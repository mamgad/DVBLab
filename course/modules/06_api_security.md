# Module 6: API Security

## Understanding API Security

### What is API Security?
API security is the practice of protecting APIs from attacks that could compromise their:
- Confidentiality (data privacy)
- Integrity (data accuracy)
- Availability (service uptime)
- Authentication (user identity)
- Authorization (user permissions)

### Common API Security Concerns

1. **Authentication Issues**
   - Missing authentication
   - Weak authentication
   - Token exposure
   - Credential leakage

2. **Authorization Flaws**
   - Missing access controls
   - Broken object-level auth
   - Excessive permissions
   - Role confusion

3. **Data Exposure**
   - Sensitive data in responses
   - Excessive data exposure
   - Unencrypted transmission
   - Debug information leaks

4. **Resource Management**
   - Missing rate limiting
   - No resource quotas
   - DoS vulnerability
   - Excessive methods

### API Attack Vectors

1. **Parameter Tampering**
   - Query manipulation
   - Body modification
   - Header injection
   - Cookie tampering

2. **API Abuse**
   - Endpoint enumeration
   - Version manipulation
   - Method spoofing
   - Content-type abuse

3. **Infrastructure Attacks**
   - SSRF
   - XXE injection
   - API gateway bypass
   - Service discovery

## DVBank API Vulnerabilities

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
- Cross-origin attacks possible
- Credential exposure
- CSRF vulnerability
- Data theft potential

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
- Brute force attacks
- DoS vulnerability
- Resource exhaustion
- Account enumeration

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
- PII exposure
- Sensitive data leakage
- Privacy violation
- Compliance issues

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

1. **CORS Security**
   - Configure proper origins
   - Test CORS policies
   - Implement preflight
   - Secure credentials

2. **Rate Limiting**
   - Add request limits
   - Implement blocking
   - Track failed attempts
   - Add retry headers

3. **Data Protection**
   - Create DTOs
   - Filter responses
   - Mask sensitive data
   - Add field policies

## Additional Resources

1. [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
2. [REST Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
3. [API Security Best Practices](https://www.pingidentity.com/en/company/blog/posts/2020/api-security-best-practices.html)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 