# Module 2: Software Composition Analysis (SCA)

## 🎯 Learning Objectives
- Learn how to perform dependency security analysis in source code reviews
- Understand how to interpret and prioritize vulnerability reports
- Practice identifying high-risk dependencies in banking applications
- Learn to write effective security findings and remediation plans

## 📚 Theoretical Background

### Why SCA in Code Reviews?
When reviewing source code for security issues, dependencies are often overlooked:
- Vulnerabilities can exist in trusted third-party code
- Legacy dependencies may contain known security issues
- Dependency versions might be pinned to vulnerable versions
- Transitive dependencies can introduce hidden risks

### Critical Areas for Banking Applications
During code review, pay special attention to dependencies handling:
- Authentication and authorization (JWT, session management)
- Data processing and serialization (YAML, JSON)
- Network communication (CORS, HTTP)
- Database interactions (ORM, connection pooling)

## 🔍 Vulnerability Analysis Example

### Sample Safety Scan Output
Below is an actual vulnerability scan of DVBank's dependencies. Let's analyze it:

```bash
$ safety scan -r requirements.txt

+======================================================================================================================+
                               /$$$$$$            /$$
                              /$$__  $$          | $$
           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$
          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$
         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$
          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$
          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$
         |_______/  \_______/|__/     \_______/   \___/   \____  $$
                                                          /$$  | $$
                                                         |  $$$$$$/
  by safetycli.com                                        \______/

Found and scanned 9 packages
15 vulnerabilities reported
```

### Understanding the Report Structure

Let's analyze key findings from the scan:

1. **PyYAML Vulnerability (High Risk)**
```
-> Vulnerability found in pyyaml version 5.3.1
   Vulnerability ID: 39611
   Affected spec: <5.4
   ADVISORY: Arbitrary code execution when processing untrusted YAML
   CVE-2020-14343
```

**Code Review Note:** During review, check for:
- YAML loading operations using unsafe `yaml.load()`
- Profile import functionality using YAML
- Configuration file processing

2. **JWT Security Issues (Critical)**
```
-> Vulnerability found in pyjwt version 2.1.0
   Vulnerability ID: 74429
   Affected spec: <2.10.1
   ADVISORY: Issuer verification bypass through partial matches
   CVE-2024-53861
```

**Code Review Note:** Search for:
- JWT token generation and validation
- Algorithm specification in JWT operations
- Issuer verification implementations

3. **Flask-CORS Vulnerabilities (Medium)**
```
-> Vulnerability found in flask-cors version 3.0.10
   Vulnerability ID: 72731
   ADVISORY: Access-Control-Allow-Private-Network CORS header issue
   CVE-2024-6221
```

**Code Review Note:** Examine:
- CORS configuration in app initialization
- Custom CORS headers and settings
- Internal network access controls

## 💡 Code Review Checklist

### 1. Dependency Declaration Review
```python
# Look for these patterns in requirements.txt
flask==2.0.1        # Fixed version - check if vulnerable
werkzeug>=2.0.1     # Floating version - check minimum bound
pyjwt~=2.1.0        # Compatible release - check major version
```

### 2. Security-Critical Code Patterns

#### YAML Processing
```python
# Vulnerable Pattern
profile_data = yaml.load(profile_yaml)  # Unsafe loading

# Secure Pattern
profile_data = yaml.safe_load(profile_yaml)  # Always use safe_load
```

#### JWT Handling
```python
# Vulnerable Pattern
token = jwt.encode(payload, key, algorithm='HS256')
data = jwt.decode(token, key)  # No algorithm verification

# Secure Pattern
token = jwt.encode(payload, key, algorithm='HS512')
data = jwt.decode(token, key, algorithms=['HS512'])  # Explicit algorithm
```

## 🛠️ Hands-on Exercise: Code Review

### Task 1: Analyze Dependencies
1. Run safety scan on the project:
```bash
safety scan -r requirements.txt --json > security-audit.json
```

2. Review the findings:
   - Group vulnerabilities by severity
   - Identify affected code paths
   - Document security implications

### Task 2: Code Review Exercise
Review this vulnerable code snippet:
```python
@auth_bp.route('/api/profile/import', methods=['POST'])
@token_required
def import_profile(current_user):
    try:
        profile_yaml = request.get_json().get('profile_yaml', '')
        # REVIEW: Unsafe YAML loading
        profile_data = yaml.load(profile_yaml, Loader=yaml.Loader)
        
        if isinstance(profile_data, dict):
            current_user.set_profile(profile_data)
            db.session.commit()
            return jsonify({'message': 'Profile imported successfully'})
        return jsonify({'error': 'Invalid profile format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400
```

**Questions:**
1. What vulnerability exists in this code?
2. How could an attacker exploit it?
3. What dependencies are involved?
4. How would you fix it?

## 📝 Writing Security Findings

### Sample Finding Report
```markdown
Title: Arbitrary Code Execution via YAML Deserialization
Severity: High
Component: PyYAML 5.3.1
Location: backend/routes/auth_routes.py:import_profile()

Description:
The profile import functionality uses unsafe YAML deserialization,
allowing arbitrary code execution through crafted YAML payloads.

Technical Details:
- CVE-2020-14343
- Unsafe yaml.load() with default Loader
- Processes untrusted user input

Impact:
An attacker can execute arbitrary code on the server by submitting
a specially crafted YAML payload through the profile import API.

Recommendation:
1. Upgrade PyYAML to >=5.4
2. Replace yaml.load() with yaml.safe_load()
3. Implement input validation for profile data
```

## 📚 Additional Resources

- [OWASP Dependency Check Guide](https://owasp.org/www-project-dependency-check/)
- [Python Safety Documentation](https://pyup.io/safety/)
- [PyYAML Security Documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [Source Code Review Guidelines](https://owasp.org/www-project-code-review-guide/) 