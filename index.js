const securityRules = {
  keywords: [
    'javascript:',
    'eval\\(',
    'setTimeout\\(',
    'setInterval\\(',
    'Function\\(',
    'constructor\\(',
    'window\\.',
    'document\\.',
    '\\.innerHtml',
    'onClick',
    'onload',
    'onerror'
  ],
  patterns: [
    '<script[^>]*>',
    'expression\\(',
    'url\\(',
    'alert\\(',
    'prompt\\(',
    'confirm\\(',
    'debugger',
    '\\.cookie'
  ]
};

const createRegexPattern = (patterns) => {
  return new RegExp(patterns.join('|'), 'gi');
};

const sanitizeValue = (value) => {
  if (typeof value !== 'string') return value;

  let sanitized = value;
  
  sanitized = sanitized.replace(createRegexPattern(securityRules.keywords), '');
  sanitized = sanitized.replace(createRegexPattern(securityRules.patterns), '');
  
  sanitized = sanitized
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\(/g, '&#40;')
    .replace(/\)/g, '&#41;')
    .replace(/'/g, '&#39;')
    .replace(/"/g, '&quot;')
    .replace(/`/g, '&#96;');
    
  return sanitized;
};

const sanitizeObject = (obj) => {
  if (typeof obj !== 'object' || obj === null) return obj;
  
  return Object.keys(obj).reduce((acc, key) => {
    const value = obj[key];
    if (typeof value === 'object') {
      acc[key] = sanitizeObject(value);
    } else {
      acc[key] = sanitizeValue(value);
    }
    return acc;
  }, Array.isArray(obj) ? [] : {});
};

const securityMiddleware = (req, res, next) => {
  try {
    if (req.query) req.query = sanitizeObject(req.query);
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.params) req.params = sanitizeObject(req.params);
    next();
  } catch (error) {
    next(error);
  }
};

module.exports = securityMiddleware;
