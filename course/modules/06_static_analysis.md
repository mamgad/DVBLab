# Module 6: Automated Static Analysis with Semgrep

## Overview

Static Analysis is a method of debugging and analyzing source code without actually executing the program. It helps identify potential bugs, security vulnerabilities, and code quality issues early in the development process.

## What is Semgrep?

Semgrep (Semantic Grep) is a fast, open-source static analysis tool that helps developers find bugs, detect vulnerabilities, and enforce code standards. It's language-aware and uses simple pattern-matching rules that look like the code you're searching for.

Key features:
- Fast and lightweight
- Language-aware analysis
- Simple, grep-like syntax
- Extensive rule registry
- CI/CD integration support

## Installation

1. **Using pip (Python Package Manager)**:
```bash
pip install semgrep
```

2. **Using Docker**:
```bash
docker pull returntocorp/semgrep
```

3. **Using Homebrew (macOS)**:
```bash
brew install semgrep
```

## Basic Usage

1. **Run a basic scan**:
```bash
semgrep scan
```

2. **Scan with specific rulesets**:
```bash
semgrep --config "p/python" .
```

3. **Output formats**:
```bash
semgrep scan --json > results.json
semgrep scan --sarif > results.sarif
```

## Real-World Example: Scanning Our Banking Application

We ran Semgrep on our vulnerable banking application, and it found 14 security issues. Let's analyze each category of findings:

### 1. Hardcoded Secrets
```python
# ❌ Vulnerable Code (backend/app.py)
app.config['SECRET_KEY'] = 'supersecret'

# ✅ Secure Fix
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
```

**Risk**: Hardcoded secrets in source code can be exposed through repository access.

### 2. SQL Injection Vulnerabilities
```python
# ❌ Vulnerable Code (backend/routes/auth_routes.py)
query = f"SELECT * FROM user WHERE username = '{username}'"
user = db.session.execute(query).fetchone()

# ✅ Secure Fix
from sqlalchemy import text
query = text("SELECT * FROM user WHERE username = :username")
user = db.session.execute(query, {'username': username}).fetchone()
```

**Risk**: SQL injection can lead to unauthorized data access or manipulation.

### 3. Debug Mode in Production
```python
# ❌ Vulnerable Code (backend/app.py)
app.run(host='0.0.0.0', debug=True, port=5000)

# ✅ Secure Fix
debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
app.run(host='0.0.0.0', debug=debug, port=5000)
```

**Risk**: Debug mode exposes sensitive information and stack traces.

### 4. JWT Security Issues
```python
# ❌ Vulnerable Code (backend/auth.py)
data = jwt.decode(token, 'secret', algorithms=['HS256'])

# ✅ Secure Fix
secret_key = os.getenv('JWT_SECRET_KEY')
data = jwt.decode(token, secret_key, algorithms=['HS256'])
```

**Risk**: Hardcoded JWT secrets can be compromised, leading to token forgery.

### 5. Password Validation
```python
# ❌ Vulnerable Code
user.set_password(password)

# ✅ Secure Fix
from django.contrib.auth.password_validation import validate_password

try:
    validate_password(password)
    user.set_password(password)
except ValidationError as e:
    raise ValueError(str(e))
```

**Risk**: Weak passwords can make accounts vulnerable to brute force attacks.

## Understanding Semgrep Results

Our scan revealed:
- Total files scanned: 36
- Total findings: 14
- Rules run: 866

Key findings breakdown:
1. Hardcoded configurations (2 instances)
2. SQL injection vulnerabilities (4 instances)
3. Debug mode issues (3 instances)
4. JWT security problems (3 instances)
5. Password validation issues (2 instances)

## Remediation Steps

1. **Environment Variables**
```bash
# .env
SECRET_KEY=your-secure-secret
JWT_SECRET=your-jwt-secret
FLASK_DEBUG=False
```

2. **Use ORM or Parameterized Queries**
```python
# Using SQLAlchemy ORM
user = User.query.filter_by(username=username).first()
```

3. **Configuration Management**
```python
# config.py
class ProductionConfig:
    DEBUG = False
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET = os.getenv('JWT_SECRET')
```

## Best Practices

1. **Regular Scanning**
   - Include Semgrep in CI/CD pipeline
   - Scan before merging code
   - Regular security audits

2. **Rule Management**
   - Use industry-standard rulesets
   - Create custom rules for project-specific needs
   - Keep rules updated

3. **Integration with Development Workflow**
   - Pre-commit hooks
   - IDE integration
   - Automated PR checks

## Exercises

1. **Run Semgrep with Different Rulesets**
```bash
# Python security rules
semgrep --config "p/python" .

# OWASP Top 10
semgrep --config "p/owasp-top-ten" .

# Custom ruleset
semgrep --config path/to/rules.yaml .
```

2. **Create Custom Rules**
```yaml
# custom-rules.yaml
rules:
  - id: detect-hardcoded-secret
    pattern: "$X = 'secret'"
    message: "Hardcoded secret detected"
    severity: ERROR
```

3. **Analyze and Fix Findings**
- Run Semgrep scan
- Categorize findings by severity
- Create remediation plan
- Implement fixes
- Verify with follow-up scan

## Additional Resources

1. [Semgrep Official Documentation](https://semgrep.dev/docs/)
2. [Semgrep Rule Registry](https://semgrep.dev/explore)
3. [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
4. [Python Security Best Practices](https://python-security.readthedocs.io/) 