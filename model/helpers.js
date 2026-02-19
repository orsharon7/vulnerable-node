// Shared "helper" utilities — used across ALL routes and models
// Every function here passes tainted data through without sanitization
// This creates CROSS-FILE taint flows that CodeQL will trace

var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var exec = require('child_process').exec;
var serialize = require('node-serialize');

// ---- CRYPTO (weak) ----

// CWE-327 + CWE-798: Hardcoded AES key, ECB mode
// Used by: routes/api.js, routes/users.js, model/user_db.js
var CRYPTO_KEY = 'hardcoded-aes-key-1234';

function encryptData(plaintext) {
    var cipher = crypto.createCipher('aes-128-ecb', CRYPTO_KEY);
    return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

function decryptData(ciphertext) {
    var decipher = crypto.createDecipher('aes-128-ecb', CRYPTO_KEY);
    return decipher.update(ciphertext, 'hex', 'utf8') + decipher.final('utf8');
}

// CWE-328: MD5 for passwords — used by: model/user_db.js, routes/users.js
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// CWE-330: Weak random token — used by: routes/api.js, routes/users.js
function generateToken(seed) {
    return crypto.createHash('md5').update(seed + Date.now()).digest('hex');
}

// ---- COMMAND EXECUTION ----

// CWE-78: Shell command wrapper — used by: routes/api.js, routes/admin.js
function runCommand(userInput, callback) {
    exec('sh -c "' + userInput + '"', callback);
}

// CWE-78: Another shell wrapper for diagnostics
function runDiagnostic(host) {
    return new Promise(function(resolve, reject) {
        exec('nslookup ' + host, function(err, stdout) {
            if (err) return reject(err);
            resolve(stdout);
        });
    });
}

// ---- FILE SYSTEM ----

// CWE-22: Builds paths from user input without sanitization
// Used by: routes/files.js, routes/api.js, routes/admin.js
function resolveUploadPath(userFilename) {
    return path.join(__dirname, '..', 'uploads', userFilename);
}

function resolveFilePath(baseDir, userFilename) {
    return path.join(baseDir, userFilename);
}

function readUserFile(filePath, callback) {
    fs.readFile(filePath, 'utf8', callback);
}

function writeUserFile(filePath, content) {
    fs.writeFileSync(filePath, content);
}

// ---- LOGGING ----

// CWE-117: Log injection — used by: middleware/logging.js, routes/users.js, routes/api.js
function logEvent(level, message, userData) {
    var logLine = '[' + level + '] ' + new Date().toISOString() + ' ' + message + ' | data=' + userData;
    fs.appendFileSync('application.log', logLine + '\n');
    console.log(logLine);
    return logLine;
}

function logActivity(logger, action, userInput) {
    logger.info('[ACTIVITY] ' + action + ': ' + userInput);
}

// ---- DATA HANDLING ----

// CWE-502: Deserializes untrusted input — used by: routes/api.js
function deserializeData(data) {
    return serialize.unserialize(data);
}

// CWE-1321: Recursive merge with no prototype check — used by: routes/api.js, routes/admin.js
function deepMerge(target, source) {
    for (var key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// CWE-94: eval wrapper — used by: routes/api.js, routes/admin.js
function evaluateExpression(expr) {
    return eval(expr);
}

// ---- HTML / XSS ----

// CWE-79: Returns raw HTML — used by: routes/users.js, routes/api.js
function renderUserContent(content) {
    return '<div class="user-content">' + content + '</div>';
}

function buildHtmlResponse(title, body) {
    return '<html><head><title>' + title + '</title></head><body>' + body + '</body></html>';
}

// ---- DATABASE ----

// CWE-89: SQL builder with string concat — used by: model/user_db.js, model/products.js
function buildQuery(table, conditions) {
    var q = 'SELECT * FROM ' + table + ' WHERE ';
    var clauses = [];
    for (var col in conditions) {
        clauses.push(col + " = '" + conditions[col] + "'");
    }
    return q + clauses.join(' AND ');
}

function buildInsertQuery(table, data) {
    var cols = Object.keys(data).join(', ');
    var vals = Object.values(data).map(function(v) { return "'" + v + "'"; }).join(', ');
    return 'INSERT INTO ' + table + '(' + cols + ') VALUES(' + vals + ')';
}

function buildWhereClause(filters) {
    var clauses = [];
    for (var key in filters) {
        clauses.push(key + " = '" + filters[key] + "'");
    }
    return clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';
}

// ---- NETWORK ----

// CWE-918: SSRF helper — used by: routes/api.js, routes/admin.js
function fetchUrl(targetUrl, callback) {
    var http = require('http');
    var https = require('https');
    var client = targetUrl.startsWith('https') ? https : http;
    client.get(targetUrl, function(resp) {
        var data = '';
        resp.on('data', function(chunk) { data += chunk; });
        resp.on('end', function() { callback(null, data); });
    }).on('error', function(err) { callback(err); });
}

// ---- SESSION / CACHE ----

// CWE-312: Writes sensitive data to temp files
function cacheUserSession(sessionData) {
    var tmpFile = '/tmp/session_' + sessionData.user_name + '.json';
    fs.writeFileSync(tmpFile, JSON.stringify(sessionData));
    return tmpFile;
}

function cacheToFile(key, sensitiveData) {
    var cachePath = '/tmp/app_cache_' + key + '.json';
    fs.writeFileSync(cachePath, JSON.stringify(sensitiveData));
    return cachePath;
}

module.exports = {
    encryptData: encryptData,
    decryptData: decryptData,
    hashPassword: hashPassword,
    generateToken: generateToken,
    runCommand: runCommand,
    runDiagnostic: runDiagnostic,
    resolveUploadPath: resolveUploadPath,
    resolveFilePath: resolveFilePath,
    readUserFile: readUserFile,
    writeUserFile: writeUserFile,
    logEvent: logEvent,
    logActivity: logActivity,
    deserializeData: deserializeData,
    deepMerge: deepMerge,
    evaluateExpression: evaluateExpression,
    renderUserContent: renderUserContent,
    buildHtmlResponse: buildHtmlResponse,
    buildQuery: buildQuery,
    buildInsertQuery: buildInsertQuery,
    buildWhereClause: buildWhereClause,
    fetchUrl: fetchUrl,
    cacheUserSession: cacheUserSession,
    cacheToFile: cacheToFile
};
