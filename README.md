# node-security-sanitizer

A Node.js middleware that sanitizes request payloads to prevent XSS and JavaScript injection attacks.

## Features

- Sanitizes query parameters, request body, and URL parameters
- Removes dangerous JavaScript keywords and functions
- Encodes HTML entities and special characters
- Handles nested objects and arrays
- Zero dependencies
- TypeScript friendly

## Installation

```bash
npm install node-security-sanitizer
```

## Usage

```javascript
const securitySanitizer = require('node-security-sanitizer');

// Express
app.use(securitySanitizer);

// Individual route
app.post('/api/data', securitySanitizer, (req, res) => {
  // Your sanitized data in req.body
});
```

## What it sanitizes

- JavaScript keywords (eval, setTimeout, etc.)
- HTML tags
- Special characters
- Common attack patterns
- Script injection attempts
- Event handlers
- DOM manipulation methods

## Example

```javascript
// Input payload
{
  "name": "Test <script>alert('xss')</script>",
  "description": "javascript:alert('hello')",
  "nested": {
    "field": "onclick=alert(1)"
  }
}

// Sanitized output
{
  "name": "Test &lt;alert('xss')&gt;",
  "description": "alert('hello')",
  "nested": {
    "field": "alert(1)"
  }
}
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

MIT

## Security

For security vulnerabilities, please contact [your-email].
