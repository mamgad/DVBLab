# DVBank Lab Course Materials

Welcome to the DVBank Lab course materials. This directory contains comprehensive modules covering various aspects of web application security, with a focus on banking applications.

## 📚 Course Index

| Module | Description | Topics Covered |
|--------|-------------|----------------|
| [📘 Module 0: Methodology](modules/00_methodology.md) | Security Assessment Methodology | - Systematic review approaches<br>- Threat modeling techniques<br>- Risk assessment frameworks |
| [📘 Module 1: Application Reconnaissance](modules/01_recon_and_mapping.md) | Understanding Application Structure | - Application exploration<br>- Code structure analysis<br>- Attack surface mapping |
| [📘 Module 2: Software Composition Analysis](modules/02_sca.md) | Dependency Security Analysis | - Vulnerability scanning<br>- Dependency review<br>- Security findings |
| [📘 Module 3: Auth & Authz](modules/03_auth_and_authz.md) | Authentication & Authorization | - JWT security<br>- Session management<br>- Access control implementation |
| [📘 Module 4: SQL Injection](modules/04_sql_injection.md) | SQL Injection Vulnerabilities | - Understanding SQL injection<br>- Real-world exploitation<br>- Prevention techniques |
| [📘 Module 5: Input Validation](modules/05_input_validation.md) | Input Validation & Sanitization | - Data validation strategies<br>- Type conversion security<br>- Input sanitization techniques |
| [📘 Module 6: API Security](modules/06_api_security.md) | API Security Best Practices | - CORS configuration<br>- Rate limiting<br>- Error handling |
| [📘 Module 7: Secure Coding](modules/07_secure_coding.md) | Secure Coding Practices | - Password security<br>- Secure logging<br>- Transaction integrity |
| [📘 Module 8: Static Analysis](modules/08_static_analysis.md) | Automated Security Analysis | - Semgrep configuration<br>- Vulnerability detection<br>- Code pattern analysis |
| [📘 Module 9: CSRF & Clickjacking](modules/09_csrf_and_clickjacking.md) | Cross-Site Request Forgery & UI Redressing | - Cookie vs token auth<br>- SameSite & CSRF tokens<br>- Anti-framing headers |
| [📘 Module 10: Stored XSS & File Upload](modules/10_xss_and_file_upload.md) | Output Encoding & Upload Security | - Stored XSS sinks<br>- Token theft via XSS<br>- Unrestricted file upload |
| [📘 Module 11: Auth Bypass & Business Logic](modules/11_auth_bypass_and_business_logic.md) | Identity & Money-Handling Flaws | - JWT none-alg bypass<br>- Insecure password reset<br>- Race conditions & negative amounts |

## 📖 Module Structure

Each module follows a consistent structure:

1. **Theoretical Background**
   - Core concepts
   - Security principles
   - Real-world implications

2. **Vulnerable Code Examples**
   - Actual code from the banking application
   - Common vulnerability patterns
   - Security anti-patterns

3. **Exploitation Techniques**
   - Step-by-step attack scenarios
   - Proof of Concept examples
   - Attack tools and methods

4. **Prevention Methods**
   - Security best practices
   - Code fixes
   - Defensive programming techniques

5. **Hands-on Exercises**
   - Practice problems
   - Code review exercises
   - Security challenges

6. **Additional Resources**
   - External references
   - Tools and documentation
   - Further reading

## 🎯 Learning Path

For optimal learning, we recommend following the modules in order:

1. Start with Module 0 to understand security assessment methodology
2. Progress through Modules 1-3 for core security concepts
3. Complete Modules 4-6 for advanced security practices
4. Review and practice with the banking application

## 🛠️ Prerequisites

- Basic understanding of Python and React
- Familiarity with web applications
- Basic knowledge of HTTP and APIs
- Development environment setup

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Documentation](https://flask.palletsprojects.com/en/2.0.x/security/)
- [React Security Best Practices](https://reactjs.org/docs/security.html)
- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Known Vulnerabilities](../docs/Vulnerabilities.md) - Complete list of intentional vulnerabilities in DVBank Lab

## ⚠️ Security Notice

The code examples in these modules contain intentional vulnerabilities for educational purposes. Never use this code in production environments. 