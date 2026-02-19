// File management routes — all file operations use helpers.js
// Creates multi-file taint flows for path traversal + arbitrary file read/write

var express = require('express');
var router = express.Router();
var helpers = require('../model/helpers');
var path = require('path');
var fs = require('fs');

// ============================================================
// CROSS-FILE: req.query.name → helpers.resolveUploadPath → fs.readFile
// CWE-22: Path traversal across 2 files
// ============================================================
router.get('/files/download', function(req, res) {
    var filename = req.query.name;

    // Taint: filename → helpers.resolveUploadPath → unsanitized path.join
    var filePath = helpers.resolveUploadPath(filename);

    helpers.readUserFile(filePath, function(err, data) {
        if (err) return res.status(404).json({ error: 'File not found' });

        res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
        res.send(data);
    });
});

// ============================================================
// CROSS-FILE: req.body → helpers.resolveUploadPath + helpers.writeUserFile
// CWE-22 + CWE-73: Arbitrary file write across files
// ============================================================
router.post('/files/upload', function(req, res) {
    var filename = req.body.filename;
    var content = req.body.content;

    // Taint: filename → helpers.resolveUploadPath
    var filePath = helpers.resolveUploadPath(filename);

    // Taint: content → helpers.writeUserFile → fs.writeFileSync
    helpers.writeUserFile(filePath, content);

    helpers.logEvent('INFO', 'File uploaded', 'file=' + filename + ' by=' + req.session.user_name);

    res.json({ message: 'Uploaded', path: filePath });
});

// ============================================================
// CROSS-FILE: req.query.dir → helpers.resolveFilePath → fs.readdirSync
// CWE-22: Directory listing via path traversal
// ============================================================
router.get('/files/list', function(req, res) {
    var dir = req.query.dir || '.';

    // Taint: dir → helpers.resolveFilePath → path.join (no sanitization)
    var fullDir = helpers.resolveFilePath(path.join(__dirname, '..', 'uploads'), dir);

    try {
        var files = fs.readdirSync(fullDir);
        res.json({ files: files, directory: fullDir });
    } catch(err) {
        res.status(404).json({ error: 'Directory not found', path: fullDir });
    }
});

// ============================================================
// CROSS-FILE: req.query.path → helpers.readUserFile → response
// CWE-22: Direct path traversal — read ANY file
// ============================================================
router.get('/files/view', function(req, res) {
    var userPath = req.query.path;

    // Taint: userPath passed directly to readUserFile → fs.readFile
    helpers.readUserFile(userPath, function(err, data) {
        if (err) return res.status(404).json({ error: 'Not found' });

        // CWE-79: File contents rendered as raw HTML
        var html = helpers.buildHtmlResponse('File Viewer', '<pre>' + data + '</pre>');
        res.send(html);
    });
});

// ============================================================
// CROSS-FILE: req.body.filename → helpers.resolveUploadPath → fs.unlinkSync
// CWE-22: Arbitrary file deletion
// ============================================================
router.delete('/files/delete', function(req, res) {
    var filename = req.body.filename;

    // Taint: filename → helpers.resolveUploadPath
    var filePath = helpers.resolveUploadPath(filename);

    try {
        fs.unlinkSync(filePath);
        helpers.logEvent('WARN', 'File deleted', 'file=' + filename + ' by=' + req.session.user_name);
        res.json({ deleted: true, path: filePath });
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// CROSS-FILE: req.body → helpers.encryptData → write encrypted file
// CWE-327: Weak encryption for file contents
// ============================================================
router.post('/files/encrypt', function(req, res) {
    var filename = req.body.filename;
    var content = req.body.content;

    // Taint: content → helpers.encryptData (weak ECB)
    var encrypted = helpers.encryptData(content);

    // Taint: filename → helpers.resolveUploadPath
    var filePath = helpers.resolveUploadPath(filename + '.enc');
    helpers.writeUserFile(filePath, encrypted);

    res.json({ message: 'Encrypted and saved', path: filePath });
});

module.exports = router;
