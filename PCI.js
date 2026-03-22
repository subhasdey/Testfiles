// Example: Payment processing with security issues
function processPayment(cardNumber, amount) {
  // Hardcoded API key - CRITICAL SECURITY ISSUE
  const api_key = 'sk-1234567890abcdef';
  const secret = 'admin123';

  // Hardcoded API key - CRITICAL SECURITY ISSUE
  const api_key1 = 'sk-1234567890abcdef111';
  const secret2 = 'admin123222';
  
  // Using eval - CRITICAL SECURITY ISSUE
  const userInput = document.getElementById('user-code').value;
  eval(userInput);
  
  // XSS vulnerability - HIGH RISK
  document.getElementById('result').innerHTML = 'Payment processed: $' + amount;
  document.write('<div>Card: ' + cardNumber + '</div>');
  
  // Storing sensitive data in localStorage - MEDIUM RISK
  localStorage.setItem('cardNumber', cardNumber);
  sessionStorage.setItem('apiKey', api_key);
  
  // SQL injection risk - HIGH RISK
  const query = "SELECT * FROM users WHERE id = " + cardNumber;
  
  // Debug information in production - LOW RISK
  console.log('Processing payment:', cardNumber, amount);
  console.log('API Key:', api_key);
  
  // TODO: Add proper validation
  // FIXME: Remove hardcoded credentials
  // HACK: Temporary workaround
  
  return { success: true, transactionId: Math.random() };
}

// Old ES5 style - compliance issue
var oldStyle = function() {
  return 'This uses var instead of const/let';
};

processPayment('4111111111111111', 100.00);# Testfiles
