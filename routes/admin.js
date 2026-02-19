var express = require('express');
var check_logged = require("./login_check");
var url = require("url");
var exec = require('child_process').exec;
var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var serialize = require('node-serialize');
var fetch = require('node-fetch');
var _ = require('lodash');
var yaml = require('js-yaml');
var jwt = require('jsonwebtoken');
var config = require('../config');
var router = express.Router();

// ============================================================
// CWE-78: OS Command Injection
// User input flows directly into child_process.exec
// ============================================================
router.get('/admin/ping', function(req, res) {

    check_logged(req, res);

    var url_params = url.parse(req.url, true).query;
    var target = url_params.target;

    // Vulnerable: user input directly in exec
    exec('ping -c 3 ' + target, function(err, stdout, stderr) {
        res.json({ output: stdout, error: stderr });
    });
});

// ============================================================
// CWE-78: Another command injection via system diagnostics
// ============================================================
router.get('/admin/system-info', function(req, res) {

    check_logged(req, res);

    var url_params = url.parse(req.url, true).query;
    var command = url_params.cmd || 'whoami';

    // Vulnerable: direct command execution from query param
    exec(command, function(err, stdout, stderr) {
        res.json({ result: stdout });
    });
});

// ============================================================
// CWE-22: Path Traversal
// User controls the file path without sanitization
// ============================================================
router.get('/admin/export', function(req, res) {

    check_logged(req, res);

    var url_params = url.parse(req.url, true).query;
    var filename = url_params.file;

    // Vulnerable: no path sanitization, allows ../../etc/passwd
    var filepath = path.join(__dirname, '..', 'exports', filename);
    
    fs.readFile(filepath, 'utf8', function(err, data) {
        if (err) {
            return res.status(404).json({ error: 'File not found' });
        }
        res.send(data);
    });
});

// ============================================================
// CWE-22: Another path traversal via file download
// ============================================================
router.get('/admin/logs', function(req, res) {

    check_logged(req, res);

    var url_params = url.parse(req.url, true).query;
    var logfile = url_params.name;

    // Vulnerable: user-controlled path used in readFile
    fs.readFile(logfile, 'utf8', function(err, data) {
        if (err) {
            return res.status(404).json({ error: 'Log not found' });
        }
        res.json({ content: data });
    });
});

// ============================================================
// CWE-918: Server-Side Request Forgery (SSRF)
// User controls the URL that the server fetches
// ============================================================
router.get('/admin/fetch-url', function(req, res) {

    check_logged(req, res);

    var url_params = url.parse(req.url, true).query;
    var target_url = url_params.url;

    // Vulnerable: server fetches any URL the user provides
    fetch(target_url)
        .then(function(response) { return response.text(); })
        .then(function(body) {
            res.json({ content: body });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message });
        });
});

// ============================================================
// CWE-328: Weak Cryptographic Hash (MD5) for passwords
// ============================================================
router.post('/admin/create-user', function(req, res) {

    check_logged(req, res);

    var username = req.body.username;
    var password = req.body.password;

    // Vulnerable: MD5 is cryptographically broken for passwords
    var hashedPassword = crypto.createHash('md5').update(password).digest('hex');

    // Also vulnerable: SQL injection
    var pgp = require('pg-promise')();
    var db = pgp(config.db.connectionString);
    var q = "INSERT INTO users(name, password) VALUES('" + username + "', '" + hashedPassword + "');";

    db.none(q)
        .then(function() {
            res.json({ message: 'User created' });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message });
        });
});

// ============================================================
// CWE-502: Insecure Deserialization
// Untrusted data passed to node-serialize
// ============================================================
router.post('/admin/import', function(req, res) {

    check_logged(req, res);

    var data = req.body.data;

    // Vulnerable: deserializing untrusted user input
    var obj = serialize.unserialize(data);

    res.json({ imported: obj });
});

// ============================================================
// CWE-1321: Prototype Pollution via lodash merge
// ============================================================
router.post('/admin/settings', function(req, res) {

    check_logged(req, res);

    var defaultSettings = {
        theme: 'light',
        language: 'en',
        notifications: true
    };

    // Vulnerable: lodash.merge with user-controlled input
    var userSettings = req.body;
    var mergedSettings = _.merge(defaultSettings, userSettings);

    res.json({ settings: mergedSettings });
});

// ============================================================
// CWE-502: Unsafe YAML deserialization
// ============================================================
router.post('/admin/import-yaml', function(req, res) {

    check_logged(req, res);

    var yamlContent = req.body.content;

    // Vulnerable: yaml.load (unsafe) instead of yaml.safeLoad
    var parsed = yaml.load(yamlContent);

    res.json({ data: parsed });
});

// ============================================================
// CWE-327: Weak JWT with hardcoded secret
// ============================================================
router.post('/admin/generate-token', function(req, res) {

    var payload = {
        user: req.body.username,
        role: 'admin',
        iat: Math.floor(Date.now() / 1000)
    };

    // Vulnerable: weak algorithm + hardcoded secret from config
    var token = jwt.sign(payload, config.jwt_secret, { algorithm: 'HS256' });

    res.json({ token: token });
});

// ============================================================
// CWE-327: Weak JWT verification (no algorithm restriction)
// ============================================================
router.get('/admin/verify-token', function(req, res) {

    var token = req.headers['x-auth-token'] || req.query.token;

    // Vulnerable: no algorithm specified, allows "none" algorithm attack
    jwt.verify(token, config.jwt_secret, function(err, decoded) {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        res.json({ user: decoded });
    });
});

// ============================================================
// CWE-200: Information Exposure via error details
// ============================================================
router.get('/admin/debug', function(req, res) {

    // Vulnerable: exposes environment variables and config
    res.json({
        env: process.env,
        config: config,
        node_version: process.version,
        platform: process.platform,
        memory: process.memoryUsage(),
        uptime: process.uptime(),
        cwd: process.cwd(),
        pid: process.pid
    });
});

// ============================================================
// CWE-79: Stored XSS via user profile
// ============================================================
router.post('/admin/profile', function(req, res) {

    check_logged(req, res);

    var bio = req.body.bio;

    // Vulnerable: storing unsanitized HTML content
    req.session.bio = bio;

    res.json({ message: 'Profile updated', bio: bio });
});

router.get('/admin/profile', function(req, res) {

    check_logged(req, res);

    // Vulnerable: renders unsanitized HTML
    res.send('<html><body><h1>Profile</h1><div>' + req.session.bio + '</div></body></html>');
});

// ============================================================
// CWE-943: NoSQL-style injection via eval
// ============================================================
router.post('/admin/calculate', function(req, res) {

    check_logged(req, res);

    var expression = req.body.expression;

    // Vulnerable: eval with user input
    var result = eval(expression);

    res.json({ result: result });
});

// ============================================================
// CWE-312: Cleartext logging of sensitive data
// ============================================================
router.post('/admin/change-password', function(req, res) {

    check_logged(req, res);

    var username = req.body.username;
    var newPassword = req.body.password;

    // Vulnerable: logging password in cleartext
    console.log('Password change for user: ' + username + ' new password: ' + newPassword);

    var hashedPassword = crypto.createHash('sha1').update(newPassword).digest('hex');

    var pgp = require('pg-promise')();
    var db = pgp(config.db.connectionString);
    var q = "UPDATE users SET password = '" + hashedPassword + "' WHERE name = '" + username + "';";

    db.none(q)
        .then(function() {
            res.json({ message: 'Password updated' });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message });
        });
});

// ============================================================
// CWE-611: XXE via XML parsing
// ============================================================
router.post('/admin/import-xml', function(req, res) {

    check_logged(req, res);

    var DOMParser = require('xmldom').DOMParser;
    var xmlContent = req.body.xml;

    // Vulnerable: XML external entity processing enabled
    var doc = new DOMParser().parseFromString(xmlContent, 'text/xml');

    res.json({ parsed: doc.toString() });
});

// ============================================================
// CWE-601: Open redirect (another instance)
// ============================================================
router.get('/admin/redirect', function(req, res) {

    var url_params = url.parse(req.url, true).query;
    var target = url_params.target;

    // Vulnerable: redirects to any user-supplied URL
    res.redirect(target);
});

module.exports = router;
