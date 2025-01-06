# Module 4: API Security

## Overview

This module covers essential API security concepts and vulnerabilities commonly found in banking applications. We'll explore CORS misconfigurations, rate limiting bypasses, and improper error handling that could lead to security breaches.

## CORS Security

### Common CORS Misconfigurations

```python
# ❌ Bad: Overly permissive CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ✅ Good: Specific origin
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
```

### Exploitable CORS Examples

```python
# ❌ Vulnerable: Reflecting Origin header
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    response.headers['Access-Control-Allow-Origin'] = origin
    return response

# ✅ Secure: Whitelist approach
ALLOWED_ORIGINS = ['http://localhost:3000', 'https://yourapp.com']
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    return response
```

## Rate Limiting

### Implementation Examples

```python
# ❌ Basic rate limiting (vulnerable to bypass)
@limiter.limit("5 per minute")
@app.route("/api/transfer")
def transfer():
    # ... transfer logic ...

# ✅ Comprehensive rate limiting
@limiter.limit("5 per minute", key_func=get_rate_limit_key)
@app.route("/api/transfer")
def transfer():
    # ... transfer logic ...

def get_rate_limit_key():
    return f"{request.remote_addr}:{get_user_id()}"
```

### Bypass Prevention

```python
# ❌ Vulnerable to header spoofing
client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

# ✅ Secure IP detection
def get_client_ip():
    if not request.headers.getlist("X-Forwarded-For"):
        return request.remote_addr
    return request.headers.getlist("X-Forwarded-For")[0]
```

## Error Handling

### Secure Error Responses

```python
# ❌ Dangerous error handling
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc()
    }), 500

# ✅ Secure error handling
@app.errorhandler(Exception)
def handle_error(error):
    app.logger.error(f"Error: {str(error)}\nTraceback: {traceback.format_exc()}")
    return jsonify({
        'error': 'An internal error occurred'
    }), 500
```

### Input Validation Errors

```python
# ❌ Revealing too much information
def validate_transfer(amount):
    if not isinstance(amount, (int, float)):
        raise ValueError(f"Expected number, got {type(amount)}")
    if amount <= 0:
        raise ValueError(f"Amount {amount} must be positive")
    if amount > get_user_balance():
        raise ValueError(f"Insufficient funds: {get_user_balance()}")

# ✅ Secure validation messages
def validate_transfer(amount):
    if not isinstance(amount, (int, float)):
        raise ValueError("Invalid amount format")
    if amount <= 0:
        raise ValueError("Amount must be positive")
    if amount > get_user_balance():
        raise ValueError("Insufficient funds")
```

## Security Headers

### Essential Headers Implementation

```python
# ✅ Secure headers configuration
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

## API Documentation Security

### Secure Swagger Configuration

```python
# ❌ Insecure Swagger UI
swagger = Swagger(app)

# ✅ Production-safe Swagger
if app.config['ENV'] == 'development':
    swagger = Swagger(app)
else:
    # Disable Swagger UI in production
    app.config['SWAGGER_UI_DOC_EXPANSION'] = None
```

## Common Vulnerabilities

### 1. Broken Authentication
- Missing or weak API keys
- Improper session handling
- Token exposure in URLs

### 2. Excessive Data Exposure
- Returning sensitive data in responses
- Lack of response filtering
- Debug information in errors

### 3. Broken Object Level Authorization
- Missing ownership checks
- Horizontal privilege escalation
- Vertical privilege escalation

### 4. Mass Assignment
- Unfiltered parameter binding
- Override of protected fields
- Automatic model mapping

## Best Practices

### 1. Authentication & Authorization
- Use strong API key schemes
- Implement proper JWT handling
- Apply role-based access control

### 2. Input Validation
- Validate all parameters
- Sanitize input data
- Use strict type checking

### 3. Output Control
- Filter sensitive data
- Implement response schemas
- Use proper error handling

### 4. Rate Limiting
- Implement per-user limits
- Use sliding windows
- Apply IP-based restrictions

## Security Testing

### 1. Authentication Tests
```python
def test_api_auth():
    # Test missing token
    response = client.get('/api/protected')
    assert response.status_code == 401
    
    # Test invalid token
    response = client.get('/api/protected', headers={'Authorization': 'Bearer invalid'})
    assert response.status_code == 401
    
    # Test expired token
    expired_token = create_expired_token()
    response = client.get('/api/protected', headers={'Authorization': f'Bearer {expired_token}'})
    assert response.status_code == 401
```

### 2. Rate Limit Tests
```python
def test_rate_limiting():
    # Test normal usage
    for _ in range(5):
        response = client.post('/api/transfer')
        assert response.status_code == 200
    
    # Test limit exceeded
    response = client.post('/api/transfer')
    assert response.status_code == 429
```

## Conclusion

### Key Takeaways
1. Always implement proper CORS policies
2. Use comprehensive rate limiting
3. Handle errors securely
4. Implement security headers
5. Follow API security best practices

### Next Steps
1. Review your API security configuration
2. Implement missing security controls
3. Add comprehensive testing
4. Monitor API usage and errors
5. Keep dependencies updated

### Additional Resources
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Flask Security Documentation](https://flask.palletsprojects.com/en/2.0.x/security/)
- [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) 