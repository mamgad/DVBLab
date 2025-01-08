# Module 3: Input Validation Vulnerabilities

## 🎓 For Beginners: Understanding Input Validation

### What is Input Validation?
Think of input validation like a bouncer at a club:
- 🚫 Checks if people are old enough to enter
- 🎫 Verifies if their ID is real
- 👥 Makes sure they're on the guest list

In code, we need to check:
1. Is the data the right type? (numbers should be numbers)
2. Is the data in the right range? (age can't be negative)
3. Is the data safe? (no harmful code or scripts)

### Common Input Problems in Simple Terms

#### 1. Missing Type Checks
Like accepting "banana" when asking for someone's age:
```python
# ❌ Bad: No type checking
@app.route('/register')
def register():
    age = request.args.get('age')  # Could be anything!
    return f"Age is {age}"

# ✅ Good: Type checking
@app.route('/register')
def register():
    try:
        age = int(request.args.get('age'))
        if age < 0 or age > 150:
            return "Invalid age"
        return f"Age is {age}"
    except ValueError:
        return "Age must be a number"
```

#### 2. Missing Range Checks
Like accepting negative money transfers:
```python
# ❌ Bad: No range check
def transfer_money(amount):
    account.balance -= amount  # Could be negative!
    
# ✅ Good: Range check
def transfer_money(amount):
    if amount <= 0:
        return "Amount must be positive"
    if amount > account.balance:
        return "Insufficient funds"
    account.balance -= amount
```

### Real-World Banking Examples

#### 1. Money Transfer Validation
```python
# ❌ Bad Implementation
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']  # Could be anything!
    make_transfer(amount)

# ✅ Good Implementation
@app.route('/transfer', methods=['POST'])
def transfer():
    try:
        amount = float(request.form['amount'])
        
        # Range checks
        if amount <= 0:
            return "Amount must be positive"
        if amount > 10000:
            return "Amount exceeds daily limit"
            
        # Decimal places check
        if len(str(amount).split('.')[-1]) > 2:
            return "Invalid amount format"
            
        make_transfer(amount)
        
    except ValueError:
        return "Invalid amount format"
```

#### 2. Account Number Validation
```python
# ❌ Bad: No format check
def validate_account(account_num):
    return len(account_num) == 10

# ✅ Good: Proper format check
def validate_account(account_num):
    if not account_num.isdigit():
        return False
    if len(account_num) != 10:
        return False
    if not account_num.startswith('2024'):
        return False
    return True
```

### Simple Tests You Can Try

#### 1. Number Fields
Try entering:
1. Letters in number fields
2. Negative numbers
3. Very large numbers
4. Decimal numbers where integers are expected

#### 2. Text Fields
Try entering:
1. Very long text
2. Special characters (!@#$%^&*)
3. HTML tags (<script>alert('hi')</script>)
4. SQL commands (SELECT * FROM users)

### Protection Checklist for Beginners

#### 1. Number Validation
- [ ] Check if input is actually a number
- [ ] Check for negative values
- [ ] Check for reasonable limits
- [ ] Check decimal places
- [ ] Check for zero where invalid

#### 2. Text Validation
- [ ] Check minimum length
- [ ] Check maximum length
- [ ] Remove dangerous characters
- [ ] Check for valid format
- [ ] Sanitize HTML/SQL content

### Common Mistakes to Avoid
1. 🚫 Trusting client-side validation only
2. 🚫 Not checking data types
3. 🚫 Forgetting about negative numbers
4. 🚫 Not limiting input length
5. 🚫 Forgetting to sanitize input

### Real-World Example: Bank Transfer Form

```python
from decimal import Decimal
import re

class TransferValidator:
    def __init__(self):
        self.errors = []
        
    def validate_amount(self, amount_str):
        try:
            # Convert to Decimal for precise money handling
            amount = Decimal(amount_str)
            
            # Basic range checks
            if amount <= 0:
                self.errors.append("Amount must be positive")
            if amount > 10000:
                self.errors.append("Amount exceeds daily limit")
                
            # Check decimal places
            if len(str(amount).split('.')[-1]) > 2:
                self.errors.append("Amount cannot have more than 2 decimal places")
                
            return amount if not self.errors else None
            
        except (ValueError, decimal.InvalidOperation):
            self.errors.append("Invalid amount format")
            return None
            
    def validate_account(self, account_num):
        # Remove spaces and dashes
        account_num = re.sub(r'[\s-]', '', account_num)
        
        if not account_num.isdigit():
            self.errors.append("Account number must contain only digits")
            return None
            
        if len(account_num) != 10:
            self.errors.append("Account number must be 10 digits")
            return None
            
        if not account_num.startswith('2024'):
            self.errors.append("Invalid account number format")
            return None
            
        return account_num
        
    def validate_description(self, text):
        # Remove dangerous characters
        text = re.sub(r'[<>\'";]', '', text)
        
        if len(text) > 100:
            self.errors.append("Description too long")
            return None
            
        return text.strip()

# Using the validator
@app.route('/transfer', methods=['POST'])
def transfer():
    validator = TransferValidator()
    
    # Validate amount
    amount = validator.validate_amount(request.form.get('amount', ''))
    
    # Validate account
    account = validator.validate_account(request.form.get('account', ''))
    
    # Validate description
    description = validator.validate_description(request.form.get('description', ''))
    
    if validator.errors:
        return jsonify({'errors': validator.errors}), 400
        
    # All validation passed, proceed with transfer
    make_transfer(amount, account, description)
    return jsonify({'message': 'Transfer successful'})
```

### Testing Your Validation

```python
def test_transfer_validation():
    validator = TransferValidator()
    
    # Test amount validation
    assert validator.validate_amount('100.50') == Decimal('100.50')
    assert validator.validate_amount('-100') is None
    assert validator.validate_amount('abc') is None
    assert validator.validate_amount('100.999') is None
    
    # Test account validation
    assert validator.validate_account('2024123456') == '2024123456'
    assert validator.validate_account('2024-123-456') == '2024123456'
    assert validator.validate_account('1234567890') is None
    assert validator.validate_account('abc') is None
    
    # Test description validation
    assert validator.validate_description('Test transfer') == 'Test transfer'
    assert validator.validate_description('<script>alert("hi")</script>') == 'scriptalert("hi")/script'
    assert validator.validate_description('a' * 200) is None
```

## Best Practices

1. Input Validation
   - Validate all user inputs
   - Use type checking
   - Implement length limits
   - Check value ranges

2. Data Sanitization
   - Sanitize before storage
   - Use HTML sanitization
   - Implement XSS protection
   - Clean special characters

3. Error Handling
   - Provide clear error messages
   - Log validation failures
   - Implement rate limiting
   - Use secure defaults

## Conclusion

Input validation and sanitization are critical security controls in banking applications. Proper implementation helps prevent a wide range of attacks, from SQL injection to XSS, ensuring the integrity and security of financial transactions.

### Key Takeaways
1. Always validate input on the server side
2. Implement proper type checking for all inputs
3. Use parameterized queries for database operations
4. Sanitize data before storage and display
5. Implement comprehensive error handling

### Next Steps
- Review all input validation mechanisms
- Implement input sanitization libraries
- Add comprehensive error handling
- Set up input validation monitoring
- Regularly test with different input types

### Additional Resources
- [OWASP Input Validation Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [SQL Injection Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Data Validation Documentation](https://www.w3.org/TR/html52/sec-forms.html#validating-form-data) 