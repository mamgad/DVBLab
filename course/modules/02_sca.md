# Module 2: Software Composition Analysis (SCA)

## 🎯 Learning Objectives
Software Composition Analysis (SCA) is a critical security practice that helps identify and manage vulnerabilities in third-party dependencies. In this module, you'll learn how to systematically analyze your application's dependencies for security issues, understand their impact, and develop effective remediation strategies.

## 📚 Theoretical Background

### Why SCA in Code Reviews?
In modern web applications, third-party dependencies make up a significant portion of the codebase. Understanding and managing these dependencies is crucial for maintaining application security. Consider these key points:
- Vulnerabilities can exist in trusted third-party code
- Legacy dependencies may contain known security issues
- Dependency versions might be pinned to vulnerable versions
- Transitive dependencies can introduce hidden risks

### Critical Areas for Banking Applications
Banking applications require special attention to dependency security due to their handling of sensitive financial data. During code review, focus on dependencies that manage:
- Authentication and authorization (JWT, session management)
- Data processing and serialization (YAML, JSON)
- Network communication (CORS, HTTP)
- Database interactions (ORM, connection pooling)

## 🔍 Vulnerability Analysis Example

### Sample Safety Scan Output
Let's examine a real vulnerability scan of DVBank's dependencies. This example demonstrates how to interpret and analyze security findings:

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
When analyzing security scan results, it's essential to understand how to interpret the findings and prioritize remediation efforts. Let's examine key findings from the scan:

1. **PyYAML Vulnerability (High Risk)**
```
-> Vulnerability found in pyyaml version 5.3.1
   Vulnerability ID: 39611
   Affected spec: <5.4
   ADVISORY: Arbitrary code execution when processing untrusted YAML
   CVE-2020-14343
```

**Code Review Note:** During your review, pay special attention to:
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

**Code Review Note:** Focus your review on:
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

**Code Review Note:** Carefully examine:
- CORS configuration in app initialization
- Custom CORS headers and settings
- Internal network access controls

## 💡 Code Review Checklist

### 1. Dependency Declaration Review
Understanding how dependencies are declared helps identify potential version-related vulnerabilities. Look for these patterns:
```python
# Look for these patterns in requirements.txt
flask==2.0.1        # Fixed version - check if vulnerable
werkzeug>=2.0.1     # Floating version - check minimum bound
pyjwt~=2.1.0        # Compatible release - check major version
```

### 2. Security-Critical Code Patterns
When reviewing code that uses external dependencies, pay attention to known vulnerable patterns and their secure alternatives:

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
Learn to perform comprehensive dependency analysis through practical exercises:
1. Run safety scan on the project:
```bash
safety scan -r requirements.txt --json > security-audit.json
```

2. Review the findings:
   - Group vulnerabilities by severity
   - Identify affected code paths
   - Document security implications

### Task 2: Code Review Exercise
Practice identifying and fixing vulnerable dependency usage patterns by reviewing this code:
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
Learning to document security findings effectively is crucial for communicating risks and remediation steps. Here's a structured approach:

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
To deepen your understanding of SCA and dependency security, explore these resources:

1. [OWASP Dependency Check Guide](https://owasp.org/www-project-dependency-check/)
2. [Python Safety Documentation](https://pyup.io/safety/)
3. [PyYAML Security Documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
4. [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
5. [Source Code Review Guidelines](https://owasp.org/www-project-code-review-guide/)

⚠️ **Remember**: These vulnerabilities are intentional for learning. Never implement such code in production environments. 