// REST API routes — every endpoint has a CROSS-FILE vulnerability
// Data flows: req → this file → model/helpers.js or model/user_db.js → sink
// CodeQL will trace taint across 2-4 files per finding

var express = require('express');
var router = express.Router();
var helpers = require('../model/helpers');
var userDb = require('../model/user_db');
var emailService = require('../services/email_service');
var exportService = require('../services/export_service');
var config = require('../config');
var url = require('url');
var fs = require('fs');
var path = require('path');

// ============================================================
// CROSS-FILE: req.query.host → helpers.runCommand → exec
// CWE-78: Command injection across 2 files
// ============================================================
router.get('/api/healthcheck', function(req, res) {
    var host = req.query.host || 'localhost';

    // Taint: req.query.host → helpers.runCommand → child_process.exec
    helpers.runCommand('ping -c 1 ' + host, function(err, stdout, stderr) {
        res.json({ status: 'ok', ping: stdout, error: stderr });
    });
});

// ============================================================
// CROSS-FILE: req.query.host → helpers.runDiagnostic → exec
// CWE-78: Another command injection path across files
// ============================================================
router.get('/api/dns-lookup', function(req, res) {
    var domain = req.query.domain;

    // Taint: domain → helpers.runDiagnostic → exec('nslookup ' + domain)
    helpers.runDiagnostic(domain)
        .then(function(result) {
            res.json({ dns: result });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message });
        });
});

// ============================================================
// CROSS-FILE: req.query.file → helpers.resolveFilePath → fs.readFile
// CWE-22: Path traversal across 2 files
// ============================================================
router.get('/api/files/read', function(req, res) {
    var filename = req.query.file;

    // Taint: filename → helpers.resolveFilePath → fs.readFile
    var fullPath = helpers.resolveFilePath(path.join(__dirname, '..', 'data'), filename);

    helpers.readUserFile(fullPath, function(err, data) {
        if (err) return res.status(404).json({ error: 'File not found' });
        res.json({ content: data });
    });
});

// ============================================================
// CROSS-FILE: req.body → helpers.writeUserFile → fs.writeFileSync
// CWE-22 + CWE-73: Arbitrary file write across files
// ============================================================
router.post('/api/files/write', function(req, res) {
    var filename = req.body.filename;
    var content = req.body.content;

    // Taint: filename → helpers.resolveUploadPath → path.join (no sanitization)
    var fullPath = helpers.resolveUploadPath(filename);

    // Taint: content → helpers.writeUserFile → fs.writeFileSync
    helpers.writeUserFile(fullPath, content);

    res.json({ message: 'File written', path: fullPath });
});

// ============================================================
// CROSS-FILE: req.body.data → helpers.deserializeData → node-serialize
// CWE-502: Deserialization across files
// ============================================================
router.post('/api/import', function(req, res) {
    var payload = req.body.data;

    // Taint: payload → helpers.deserializeData → serialize.unserialize
    var obj = helpers.deserializeData(payload);

    res.json({ imported: obj });
});

// ============================================================
// CROSS-FILE: req.body → helpers.deepMerge → prototype pollution
// CWE-1321: Prototype pollution across files (different path than admin.js)
// ============================================================
router.post('/api/config', function(req, res) {
    var baseConfig = {
        apiVersion: 'v1',
        rateLimit: 100,
        debug: false
    };

    // Taint: req.body → helpers.deepMerge → object
    var merged = helpers.deepMerge(baseConfig, req.body);

    res.json({ config: merged });
});

// ============================================================
// CROSS-FILE: req.body.expr → helpers.evaluateExpression → eval
// CWE-94: Code injection across files
// ============================================================
router.post('/api/calculate', function(req, res) {
    var expression = req.body.expression;

    // Taint: expression → helpers.evaluateExpression → eval()
    var result = helpers.evaluateExpression(expression);

    res.json({ result: result });
});

// ============================================================
// CROSS-FILE: req.query.url → helpers.fetchUrl → http.get
// CWE-918: SSRF across files
// ============================================================
router.get('/api/proxy', function(req, res) {
    var targetUrl = req.query.url;

    // Taint: targetUrl → helpers.fetchUrl → http.get(url)
    helpers.fetchUrl(targetUrl, function(err, data) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ response: data });
    });
});

// ============================================================
// CROSS-FILE: req.body → helpers.encryptData → weak crypto → response
// CWE-327: Weak crypto across files
// ============================================================
router.post('/api/encrypt', function(req, res) {
    var plaintext = req.body.text;

    // Taint: plaintext → helpers.encryptData → aes-128-ecb
    var encrypted = helpers.encryptData(plaintext);

    // Also: CWE-312 — cache plaintext to file
    helpers.cacheToFile('api_encrypt_' + Date.now(), { input: plaintext, output: encrypted });

    res.json({ encrypted: encrypted });
});

router.post('/api/decrypt', function(req, res) {
    var ciphertext = req.body.text;

    // Taint: ciphertext → helpers.decryptData → aes-128-ecb
    var decrypted = helpers.decryptData(ciphertext);

    res.json({ decrypted: decrypted });
});

// ============================================================
// CROSS-FILE: req.body → helpers.buildInsertQuery → SQL
// CWE-89: SQL injection across files
// ============================================================
router.post('/api/data', function(req, res) {
    var table = req.body.table;
    var data = req.body.record;

    // Taint: table + data → helpers.buildInsertQuery → SQL string concat
    var query = helpers.buildInsertQuery(table, data);

    userDb.rawQuery(query)
        .then(function(result) {
            res.json({ inserted: true });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message, query: query });
        });
});

// ============================================================
// CROSS-FILE: req.body → helpers.renderUserContent → XSS response
// CWE-79: Reflected XSS across files
// ============================================================
router.post('/api/preview', function(req, res) {
    var content = req.body.html;

    // Taint: content → helpers.renderUserContent → raw HTML
    var rendered = helpers.renderUserContent(content);

    // Taint: req.body.title → helpers.buildHtmlResponse → raw HTML
    var page = helpers.buildHtmlResponse(req.body.title || 'Preview', rendered);

    res.send(page);
});

// ============================================================
// CROSS-FILE: req.query → helpers.buildQuery + userDb.rawQuery
// CWE-89: SQL injection across 3 files (route → helper → db)
// ============================================================
router.get('/api/query', function(req, res) {
    var table = req.query.table;
    var filters = {};

    // Build filters from all query params except 'table'
    var params = url.parse(req.url, true).query;
    for (var key in params) {
        if (key !== 'table') filters[key] = params[key];
    }

    // Taint: table + filters → helpers.buildQuery → SQL
    var query = helpers.buildQuery(table, filters);

    userDb.rawQuery(query)
        .then(function(data) {
            res.json({ data: data });
        })
        .catch(function(err) {
            // CWE-209: Leaks full query and error to client
            res.status(500).json({ error: err.message, query: query });
        });
});

// ============================================================
// CROSS-FILE: req.body → helpers.logEvent → log injection → file
// CWE-117: Log injection across files
// ============================================================
router.post('/api/feedback', function(req, res) {
    var name = req.body.name;
    var message = req.body.message;
    var rating = req.body.rating;

    // Taint: name + message → helpers.logEvent → file write
    helpers.logEvent('FEEDBACK', 'User feedback from ' + name, 'message=' + message + ' rating=' + rating);

    res.json({ message: 'Feedback received' });
});

// ============================================================
// CROSS-FILE: req.body → userDb.createUser → helpers.hashPassword → SQL
// CWE-89 + CWE-328: 3-file taint flow
// ============================================================
router.post('/api/admin/users', function(req, res) {
    // CWE-285: Only checks a header, no real auth
    if (req.headers['x-user-role'] !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;
    var role = req.body.role;

    var hashed = helpers.hashPassword(password);

    userDb.createUser(username, hashed, email, role)
        .then(function() {
            // CWE-312: Log sensitive data
            helpers.logEvent('ADMIN', 'Created user', 'user=' + username + ' pass=' + password + ' role=' + role);
            res.json({ created: true });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message, stack: err.stack });
        });
});

// ============================================================
// CROSS-FILE: req.body → userDb.deleteUser → SQL
// CWE-89 + CWE-285: SQL injection + broken access control
// ============================================================
router.delete('/api/admin/users/:id', function(req, res) {
    if (!req.isAdmin) {
        return res.status(403).json({ error: 'Admin required' });
    }

    // Taint: req.params.id → userDb.deleteUser → SQL concat
    userDb.deleteUser(req.params.id)
        .then(function() {
            res.json({ deleted: true });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message });
        });
});

// ============================================================
// 4-FILE CHAIN: req.body → api.js → emailService → helpers → exec
// CWE-78: Command injection 4 files deep
// ============================================================
router.post('/api/send-notification', function(req, res) {
    var email = req.body.email;
    var username = req.body.username;
    var message = req.body.message;

    // Taint: email → emailService.sendWelcomeEmail → exec('echo ... | sendmail ' + email)
    emailService.sendWelcomeEmail(email, username);

    // Taint: message → emailService.buildEmailHtml → unsanitized HTML
    var html = emailService.buildEmailHtml(username, message);

    res.send(html);
});

// ============================================================
// 4-FILE CHAIN: req → api.js → exportService → helpers → userDb → SQL
// CWE-89 + CWE-22: SQL injection + path traversal 4 files deep
// ============================================================
router.post('/api/export', function(req, res) {
    var table = req.body.table;
    var filters = req.body.filters || {};
    var outputPath = req.body.output_path;

    // Taint: table+filters → exportService → helpers.buildQuery → SQL injection
    // Taint: outputPath → exportService → fs.writeFileSync (path traversal)
    exportService.exportQueryToFile(table, filters, outputPath, function(err, filepath) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ exported: filepath });
    });
});

// ============================================================
// 4-FILE CHAIN: req → api.js → exportService → helpers → node-serialize
// CWE-502 + CWE-22: Deserialization + path traversal
// ============================================================
router.post('/api/import-file', function(req, res) {
    var filePath = req.body.file_path;

    // Taint: filePath → exportService.importFromFile → helpers.readUserFile → helpers.deserializeData
    exportService.importFromFile(filePath, function(err, data) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ data: data });
    });
});

// ============================================================
// 4-FILE CHAIN: req → api.js → exportService → exec
// CWE-78: Command injection via report format
// ============================================================
router.post('/api/report', function(req, res) {
    var format = req.body.format;
    var title = req.body.title;

    // Taint: format → exportService.generateReport → exec('wkhtmlto' + format + ...)
    exportService.generateReport(format, title, { generated: new Date() }, function(err, filepath) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ report: filepath });
    });
});

// ============================================================
// 4-FILE CHAIN: req → api.js → emailService → helpers.fetchUrl → SSRF
// CWE-918: SSRF via email template URL
// ============================================================
router.post('/api/email-template', function(req, res) {
    var templateUrl = req.body.template_url;

    // Taint: templateUrl → emailService.loadEmailTemplate → helpers.fetchUrl → http.get
    emailService.loadEmailTemplate(templateUrl, function(err, html) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ template: html });
    });
});

// ============================================================
// 3-FILE CHAIN: req → api.js → emailService → helpers → log + exec
// CWE-78: Command injection via attachment path
// ============================================================
router.post('/api/send-report', function(req, res) {
    var email = req.body.email;
    var subject = req.body.subject;
    var attachmentPath = req.body.attachment;

    // Taint: email + subject + attachmentPath → emailService → exec
    emailService.sendEmailWithAttachment(email, subject, attachmentPath);

    res.json({ message: 'Report sent' });
});

module.exports = router;
