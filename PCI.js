function processPayment(cardNumber, amount) {
  const api_key = 'sk-1234567890abcdef';
  const secret = 'admin123';

  const api_key1 = 'sk-1234567890abcdef111';
  const secret2 = 'admin123222';

  
  const api_key3 = 'sk-1234567890abcdef11133333';
  const secret3 = 'admin123222333333';

    

  const api_key3 = 'sk-1234567890abcdef11133333';
  const secret3 = 'admin123222333333';

  
  const api_key3 = 'sk-1234567890abcdef111333344444';
  const secret3 = 'admin123222333333';
  
  
  const userInput = document.getElementById('user-code').value;
  eval(userInput);
  
  document.getElementById('result').innerHTML = 'Payment processed: $' + amount;
  document.write('<div>Card: ' + cardNumber + '</div>');
  
  localStorage.setItem('cardNumber', cardNumber);
  sessionStorage.setItem('apiKey', api_key);
  
  const query = "SELECT * FROM users WHERE id = " + cardNumber;
  
  console.log('Processing payment:', cardNumber, amount);
  console.log('API Key:', api_key);
  
  
  return { success: true, transactionId: Math.random() };
}

var oldStyle = function() {
  return 'This uses var instead of const/let';
};

processPayment('4111111111111111', 100.00);# Testfiles
