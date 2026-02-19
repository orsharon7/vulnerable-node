// User management routes — demonstrates CROSS-FILE taint flows
// User input → this file → model/helpers.js → model/user_db.js → database
// CodeQL traces: req.body.password → helpers.hashPassword → user_db.createUser → SQL

var express = require('express');
var router = express.Router();
var helpers = require('../model/helpers');
var userDb = require('../model/user_db');
var emailService = require('../services/email_service');
var config = require('../config');
var jwt = require('jsonwebtoken');
var crypto = require('crypto');

// ============================================================
// CROSS-FILE: req.body → helpers.hashPassword → userDb.createUser → SQL
// CWE-328 (helpers.js) + CWE-89 (user_db.js)
// ============================================================
router.post('/users/register', function(req, res) {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;
    var role = req.body.role; // CWE-285: user controls their own role

    // Taint: password → helpers.hashPassword (MD5)
    var hashed = helpers.hashPassword(password);

    // Taint: username, email, role → userDb.createUser → SQL concat
    userDb.createUser(username, hashed, email, role)
        .then(function(user) {
            // CWE-312: Logs password hash and sensitive data
            helpers.logEvent('INFO', 'User registered', 'user=' + username + ' email=' + email + ' hash=' + hashed);
            // CWE-327: Encrypts session token with weak crypto
            var token = helpers.encryptData(username + ':' + Date.now());

            // 4-FILE CHAIN: req.body.email → users.js → emailService → helpers → exec
            emailService.sendWelcomeEmail(email, username);

            // Verification token through helpers (weak crypto chain)
            var verification = emailService.generateEmailVerificationToken(email);

            res.json({ message: 'User created', token: token, verification: verification.token });
        })
        .catch(function(err) {
            // CWE-209: Error details leak to client
            res.status(500).json({ error: err.message, stack: err.stack });
        });
});

// ============================================================
// CROSS-FILE: req.body → helpers.hashPassword → userDb.authenticate → SQL
// CWE-89 across 3 files: routes/users.js → model/helpers.js → model/user_db.js
// ============================================================
router.post('/users/login', function(req, res) {
    var username = req.body.username;
    var password = req.body.password;

    // Taint flows: password → helpers → userDb → SQL
    var hashed = helpers.hashPassword(password);

    userDb.authenticate(username, hashed)
        .then(function(user) {
            req.session.logged = true;
            req.session.user_name = username;
            req.session.user_role = user.role;

            // CWE-312: Cache full session to temp file
            helpers.cacheUserSession(req.session);

            // CWE-327: Weak JWT with hardcoded secret from config.js
            var token = jwt.sign(
                { user: username, role: user.role, admin: true },
                config.jwt_secret,
                { algorithm: 'HS256', expiresIn: '999d' }
            );

            // CWE-614: Cookie without secure flag
            res.cookie('auth_token', token, { httpOnly: false, secure: false });
            res.json({ message: 'Login successful', token: token, user: user });
        })
        .catch(function(err) {
            helpers.logEvent('WARN', 'Login failed', 'user=' + username + ' password=' + password);
            res.status(401).json({ error: 'Authentication failed', details: err.message });
        });
});

// ============================================================
// CROSS-FILE: req.query → userDb.findUser → SQL injection
// CWE-89: user_db.js builds query with string concat
// ============================================================
router.get('/users/profile', function(req, res) {
    var userId = req.query.id;

    // Taint: userId → userDb.findUser → SQL concat
    userDb.findUser(userId)
        .then(function(user) {
            // CWE-79: renders user bio as raw HTML
            var html = helpers.buildHtmlResponse(
                'Profile - ' + user.name,
                '<h1>' + user.name + '</h1><div>' + user.bio + '</div><p>Email: ' + user.email + '</p>'
            );
            res.send(html);
        })
        .catch(function(err) {
            res.status(404).json({ error: err.message });
        });
});

// ============================================================
// CROSS-FILE: req.body → helpers.renderUserContent → response (XSS)
// CWE-79 across files: input in routes/users.js, sink in model/helpers.js
// ============================================================
router.post('/users/profile/update', function(req, res) {
    var bio = req.body.bio;
    var website = req.body.website;
    var displayName = req.body.display_name;

    // Taint: bio → helpers.renderUserContent → response
    var renderedBio = helpers.renderUserContent(bio);

    // Taint: displayName, website, bio → userDb.updateProfile → SQL
    userDb.updateProfile(req.session.user_name, { bio: bio, website: website, display_name: displayName })
        .then(function() {
            res.send(renderedBio);
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message });
        });
});

// ============================================================
// CROSS-FILE: req.body → helpers.encryptData → response
// CWE-327: encryption with ECB mode from helpers.js
// ============================================================
router.post('/users/encrypt-data', function(req, res) {
    var sensitiveData = req.body.data;

    // Taint: user data → helpers.encryptData (weak ECB)
    var encrypted = helpers.encryptData(sensitiveData);

    // Also cache the plaintext to disk
    helpers.cacheToFile(req.session.user_name, { plain: sensitiveData, encrypted: encrypted });

    res.json({ encrypted: encrypted });
});

// ============================================================
// CROSS-FILE: req.query → helpers.buildQuery → SQL injection
// CWE-89: helpers.js builds SQL, user_db.js executes it
// ============================================================
router.get('/users/search', function(req, res) {
    var filters = {
        name: req.query.name,
        email: req.query.email,
        role: req.query.role
    };

    // Clean out undefined values
    Object.keys(filters).forEach(function(k) { if (!filters[k]) delete filters[k]; });

    // Taint: req.query → helpers.buildQuery → SQL string
    var query = helpers.buildQuery('users', filters);

    userDb.rawQuery(query)
        .then(function(users) {
            res.json({ users: users });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message, query: query });
        });
});

// ============================================================
// CROSS-FILE: req.headers → jwt.verify → userDb → SQL
// CWE-327 + CWE-285: JWT from config.js, no algorithm restriction
// ============================================================
router.get('/users/me', function(req, res) {
    var token = req.headers['authorization'] || req.query.token;

    // CWE-327: no algorithms restriction allows "none" attack
    jwt.verify(token, config.jwt_secret, function(err, decoded) {
        if (err) return res.status(401).json({ error: 'Invalid token' });

        // Taint: decoded.user (from JWT) → userDb.findByName → SQL
        userDb.findByName(decoded.user)
            .then(function(user) {
                // CWE-200: returns full user object including password hash
                res.json(user);
            })
            .catch(function(err) {
                res.status(500).json({ error: err.message });
            });
    });
});

// ============================================================
// CROSS-FILE: req.body → helpers.deepMerge → prototype pollution
// CWE-1321: user controls merge source
// ============================================================
router.put('/users/preferences', function(req, res) {
    var defaults = { theme: 'light', lang: 'en', notifications: true };

    // Taint: req.body → helpers.deepMerge → object pollution
    var prefs = helpers.deepMerge(defaults, req.body);

    userDb.savePreferences(req.session.user_name, prefs)
        .then(function() {
            res.json({ preferences: prefs });
        })
        .catch(function(err) {
            res.status(500).json({ error: err.message });
        });
});

module.exports = router;
