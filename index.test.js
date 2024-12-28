const securityMiddleware = require('./index');

describe('Security Middleware', () => {
    let req, res, next;

    beforeEach(() => {
        req = {
            query: {},
            body: {},
            params: {}
        };
        res = {};
        next = jest.fn();
    });

    test('should sanitize script tags', () => {
        req.body.content = '<script>alert("xss")</script>';
        securityMiddleware(req, res, next);
        expect(req.body.content).toBe('&quot;xss&quot;&#41;&lt;/script&gt;');
    });

    test('should sanitize nested objects', () => {
        req.body = {
            level1: {
                level2: '<script>evil()</script>'
            }
        };
        securityMiddleware(req, res, next);
        expect(req.body.level1.level2).toBe('evil&#40;&#41;&lt;/script&gt;');
    });

    test('should handle arrays', () => {
        req.body.items = ['<script>a()</script>', '<script>b()</script>'];
        securityMiddleware(req, res, next);
        expect(req.body.items).toEqual(['a&#40;&#41;&lt;/script&gt;', 'b&#40;&#41;&lt;/script&gt;']);
    });

    test('should sanitize query parameters', () => {
        req.query.search = 'javascript:alert(1)';
        securityMiddleware(req, res, next);
        expect(req.query.search).toBe('1&#41;');
    });

    test('should encode special characters', () => {
        req.body.text = '(<script>)';
        securityMiddleware(req, res, next);
        expect(req.body.text).toBe('&#40;&#41;');
    });

    test('should handle non-string values', () => {
        req.body = {
            number: 123,
            boolean: true,
            null: null
        };
        securityMiddleware(req, res, next);
        expect(req.body).toEqual({
            number: 123,
            boolean: true,
            null: null
        });
    });

    test('should remove dangerous keywords', () => {
        req.body.code = 'eval(alert())';
        securityMiddleware(req, res, next);
        expect(req.body.code).toBe('&#41;&#41;');
    });

    test('should handle empty objects', () => {
        securityMiddleware(req, res, next);
        expect(req.body).toEqual({});
        expect(next).toHaveBeenCalled();
    });

    test('should catch and pass errors', () => {
        req.body = null;
        securityMiddleware(req, res, next);
        expect(next).toHaveBeenCalled();
    });
});