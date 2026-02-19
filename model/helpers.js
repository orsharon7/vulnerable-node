// "Helper" utilities written by a bad developer
// Used across routes and models -- tainted data flows through these

var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var exec = require('child_process').exec;

// CWE-327: Weak encryption used across the app for "securing" data
// Called from routes/products.js and routes/api.js
function encryptData(data) {
    var key = 'hardcoded-aes-key-1234'; // CWE-798: hardcoded crypto key
    var cipher = crypto.createCipher('aes-128-ecb', key); // CWE-327: weak mode ECB
    var encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptData(data) {
    var key = 'hardcoded-aes-key-1234';
    var decipher = crypto.createDecipher('aes-128-ecb', key);
    var decrypted = decipher.update(data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// CWE-328: Weak hash used as "token generator" -- called from login route
function generateToken(username) {
    return crypto.createHash('md5').update(username + Date.now()).digest('hex');
}

// CWE-22: Unsanitized path builder -- called from multiple routes
function resolveUploadPath(userFilename) {
    return path.join(__dirname, '..', 'uploads', userFilename);
}

// CWE-78: Shell wrapper -- called from routes/api.js
function runDiagnostic(host) {
    return new Promise(function(resolve, reject) {
        exec('nslookup ' + host, function(err, stdout, stderr) {
            if (err) return reject(err);
            resolve(stdout);
        });
    });
}

// CWE-117: Log injection -- called from multiple routes
function logActivity(logger, action, userInput) {
    logger.info('[ACTIVITY] ' + action + ': ' + userInput);
}

// CWE-312: Writes sensitive data to a temp file -- called from routes/products.js
function cacheUserSession(sessionData) {
    var tmpFile = '/tmp/session_' + sessionData.user_name + '.json';
    fs.writeFileSync(tmpFile, JSON.stringify(sessionData));
    return tmpFile;
}

// Build a WHERE clause from user input -- reused in multiple models
// CWE-89: SQL injection helper used everywhere
function buildWhereClause(filters) {
    var clauses = [];
    for (var key in filters) {
        clauses.push(key + " = '" + filters[key] + "'");
    }
    return clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';
}

module.exports = {
    encryptData: encryptData,
    decryptData: decryptData,
    generateToken: generateToken,
    resolveUploadPath: resolveUploadPath,
    runDiagnostic: runDiagnostic,
    logActivity: logActivity,
    cacheUserSession: cacheUserSession,
    buildWhereClause: buildWhereClause
};
