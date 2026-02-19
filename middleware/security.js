// Middleware that processes requests BEFORE they hit route handlers
// Injects vulnerable behavior into the request pipeline across all routes

var helpers = require('../model/helpers');
var fs = require('fs');

// CWE-117 + CWE-312: Logs every request including sensitive headers and body
// Taint flow: req.headers/req.body → helpers.logEvent → file + console
function requestLogger(req, res, next) {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var userAgent = req.headers['user-agent'];
    var authHeader = req.headers['authorization'] || 'none';

    // Logs auth tokens in cleartext
    helpers.logEvent('ACCESS', req.method + ' ' + req.url, 
        'ip=' + ip + ' agent=' + userAgent + ' auth=' + authHeader);

    // Also log full body for POST requests (passwords, tokens, etc.)
    if (req.body && Object.keys(req.body).length > 0) {
        helpers.logEvent('BODY', req.url, JSON.stringify(req.body));
    }

    next();
}

// CWE-1321: Merges request headers into app config — prototype pollution
// Taint flow: req.headers['x-custom-config'] → helpers.deepMerge → app config
function configOverride(req, res, next) {
    var customConfig = req.headers['x-custom-config'];
    if (customConfig) {
        try {
            var overrides = JSON.parse(customConfig);
            req.appConfig = helpers.deepMerge({}, overrides);
        } catch(e) {
            req.appConfig = {};
        }
    }
    next();
}

// CWE-312: Caches full session data including credentials to temp files
// Taint flow: req.session → helpers.cacheUserSession → /tmp file
function sessionCache(req, res, next) {
    if (req.session && req.session.logged) {
        helpers.cacheUserSession({
            user_name: req.session.user_name,
            session_id: req.sessionID,
            logged: req.session.logged,
            cookies: req.headers.cookie
        });
    }
    next();
}

// CWE-79: Adds unsanitized user input to response locals for templates
// Taint flow: req.query.theme → res.locals → EJS templates
function themeMiddleware(req, res, next) {
    res.locals.customTheme = req.query.theme || 'default';
    res.locals.customCss = req.query.css || '';
    res.locals.greeting = req.query.greeting || 'Welcome';
    // These get rendered directly in EJS without escaping:  <%- customTheme %>
    next();
}

// CWE-285: Broken access control — trusts client-supplied role header
function roleFromHeader(req, res, next) {
    // Trusts the client to declare their own role
    req.userRole = req.headers['x-user-role'] || 'guest';
    req.isAdmin = (req.userRole === 'admin');
    next();
}

// CWE-346: Missing CORS / origin validation
function permissiveCors(req, res, next) {
    var origin = req.headers['origin'];
    // Reflects any origin — allows credential theft from any domain
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Allow-Methods', '*');
    next();
}

// CWE-200: Exposes server internals in response headers
function debugHeaders(req, res, next) {
    res.setHeader('X-Powered-By', 'Express 4.13.1');
    res.setHeader('X-Server-Hostname', require('os').hostname());
    res.setHeader('X-Node-Version', process.version);
    res.setHeader('X-Process-Id', process.pid.toString());
    next();
}

module.exports = {
    requestLogger: requestLogger,
    configOverride: configOverride,
    sessionCache: sessionCache,
    themeMiddleware: themeMiddleware,
    roleFromHeader: roleFromHeader,
    permissiveCors: permissiveCors,
    debugHeaders: debugHeaders
};
