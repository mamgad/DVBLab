# Module 3: Authentication & Authorization Vulnerabilities

## 🎓 For Beginners: Understanding Auth Vulnerabilities

### What's the Difference?
- 🔐 **Authentication** = Proving who you are (like showing your ID)
- 🎫 **Authorization** = Proving what you're allowed to do (like having a VIP ticket)

Think of it like a concert:
1. Authentication: Showing your ID to prove you're on the guest list
2. Authorization: Your ticket determines if you can go backstage

### Common Auth Problems in Simple Terms

#### 1. Weak Authentication
Imagine a door with a lock:
- ❌ Bad Lock: Using "password123" as your password
- ✅ Good Lock: Using a strong, unique password

Example of weak authentication:
```python
# ❌ Bad: Simple password check
if password == "admin123":
    let_user_in()

# ✅ Good: Proper password hashing
if check_password_hash(stored_hash, user_password):
    let_user_in()
```

#### 2. Missing Authorization
Like a hotel where all room keys open all doors:
```python
# ❌ Bad: No authorization check
@app.route('/account/<account_id>')
def view_account(account_id):
    return get_account_details(account_id)  # Anyone can view any account!

# ✅ Good: Proper authorization
@app.route('/account/<account_id>')
@login_required
def view_account(account_id):
    if account_id != current_user.id:
        return "Access denied"
    return get_account_details(account_id)
```

### JWT Tokens for Beginners

#### What is a JWT?
Think of it like a special ID card that:
1. Contains your information (like a driver's license)
2. Can't be faked (it's digitally signed)
3. Has an expiration date

```python
# Structure of a JWT
header = {
    "type": "JWT",
    "algorithm": "HS256"
}
payload = {
    "user_id": 123,
    "username": "alice",
    "expires": "2024-01-05"
}
signature = HMAC_SHA256(base64(header) + base64(payload), secret_key)
```

#### Common JWT Mistakes
1. ❌ Using a weak secret key:
```python
# ❌ Bad: Weak secret
jwt_secret = "secret123"  # Easy to guess!

# ✅ Good: Strong secret
jwt_secret = os.environ.get('JWT_SECRET_KEY')  # Long, random, secure
```

2. ❌ Not checking expiration:
```python
# ❌ Bad: No expiration check
token = jwt.encode({'user_id': 123}, secret)

# ✅ Good: Proper expiration
token = jwt.encode({
    'user_id': 123,
    'exp': datetime.utcnow() + timedelta(hours=1)
}, secret)
```

### Authorization Problems for Beginners

#### 1. Insecure Direct Object References (IDOR)
Imagine a bank website where changing the URL number lets you see other people's accounts:

```python
# ❌ Bad: No ownership check
@app.route('/api/statement/<statement_id>')
def get_statement(statement_id):
    return Statement.get(statement_id)  # Anyone can access any statement!

# ✅ Good: Ownership check
@app.route('/api/statement/<statement_id>')
@login_required
def get_statement(statement_id):
    statement = Statement.get(statement_id)
    if statement.user_id != current_user.id:
        return "Access denied"
    return statement
```

#### 2. Missing Role Checks
Like letting any employee access the bank vault:

```python
# ❌ Bad: No role check
@app.route('/admin/users')
@login_required
def list_users():
    return User.get_all()  # Any logged-in user can access!

# ✅ Good: Role check
@app.route('/admin/users')
@login_required
@require_role('admin')
def list_users():
    return User.get_all()  # Only admins can access
```

### Simple Tests for Beginners

#### 1. Authentication Tests
Try these:
1. Use a very simple password (like "password123")
2. Try logging in with SQL injection
3. Try using an expired token
4. Try modifying a JWT token

#### 2. Authorization Tests
Look for:
1. Change numbers in URLs (like /account/1 to /account/2)
2. Try accessing admin pages as a regular user
3. Try modifying your user role in tokens
4. Check if you can access other users' data

### Protection Checklist for Beginners

#### 1. Authentication
- [ ] Use strong password requirements
- [ ] Implement proper session management
- [ ] Use secure token generation
- [ ] Add two-factor authentication
- [ ] Rate limit login attempts

#### 2. Authorization
- [ ] Check user permissions for every action
- [ ] Implement proper role-based access control
- [ ] Validate user ownership of resources
- [ ] Log all access attempts
- [ ] Use principle of least privilege

### Real-World Example
Let's say you're building a banking app:

```python
# ❌ Bad Implementation
@app.route('/transfer', methods=['POST'])
def transfer_money():
    from_account = request.form['from']
    to_account = request.form['to']
    amount = request.form['amount']
    
    # No authentication or authorization!
    make_transfer(from_account, to_account, amount)

# ✅ Good Implementation
@app.route('/transfer', methods=['POST'])
@login_required  # Authentication
def transfer_money():
    from_account = request.form['from']
    to_account = request.form['to']
    amount = request.form['amount']
    
    # Authorization
    if not owns_account(current_user, from_account):
        return "Access denied", 403
        
    # Validation
    if not is_valid_amount(amount):
        return "Invalid amount", 400
        
    # Logging
    audit_log.info(f"Transfer initiated by {current_user.id}")
    
    # Execute
    make_transfer(from_account, to_account, amount)
```

### Common Mistakes to Avoid
1. 🚫 Using client-side only validation
2. 🚫 Trusting user input without verification
3. 🚫 Hardcoding secrets in code
4. 🚫 Not expiring tokens
5. 🚫 Missing access controls

## Conclusion

### Key Takeaways
1. Always implement both authentication AND authorization - they work together to create a secure system
2. Use industry-standard libraries and frameworks instead of building your own auth system
3. Follow the principle of least privilege - users should only have access to what they need
4. Keep security tokens (like JWTs) secure and implement proper expiration
5. Log and monitor authentication and authorization events for security auditing

### Best Practices Checklist
- [ ] Implement strong password policies
- [ ] Use secure session management
- [ ] Apply proper access controls on all endpoints
- [ ] Validate user permissions for every action
- [ ] Implement proper error handling without leaking sensitive information
- [ ] Use HTTPS for all authentication requests
- [ ] Implement rate limiting for login attempts
- [ ] Regular security audits of auth systems

### Next Steps
1. Review your application's current auth implementation
2. Test for common vulnerabilities using the techniques learned
3. Implement missing security controls
4. Set up proper logging and monitoring
5. Consider adding additional security layers like 2FA

### Additional Resources
- [OWASP Authentication Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-bcp)
- [Session Management Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

### Practice Lab
Try exploiting the authentication vulnerabilities in our DVB Lab environment:
1. Attempt JWT token manipulation
2. Test session management weaknesses
3. Try bypassing authentication controls
4. Exploit weak password policies

Remember to document your findings and implement the security fixes using the techniques learned in this module. 