// Email notification service — uses helpers.js for crypto and logging
// Called from: routes/users.js, routes/api.js
// Creates cross-file chains: route → email_service → helpers → sink

var helpers = require('../model/helpers');
var config = require('../config');
var exec = require('child_process').exec;
var fs = require('fs');

// CWE-78: Command injection — user-controlled email address in sendmail command
// Called from: routes/users.js on registration
function sendWelcomeEmail(toAddress, username) {
    // Taint: toAddress → exec (command injection via email field)
    var cmd = 'echo "Welcome ' + username + '" | sendmail ' + toAddress;
    exec(cmd, function(err) {
        if (err) helpers.logEvent('ERROR', 'Email failed', 'to=' + toAddress);
    });
    helpers.logEvent('INFO', 'Welcome email sent', 'to=' + toAddress + ' user=' + username);
}

// CWE-78: Command injection via attachment filename
function sendEmailWithAttachment(toAddress, subject, attachmentPath) {
    var cmd = 'mail -s "' + subject + '" -a ' + attachmentPath + ' ' + toAddress;
    exec(cmd, function(err) {
        if (err) helpers.logEvent('ERROR', 'Attachment email failed', 'to=' + toAddress);
    });
}

// CWE-327 + CWE-312: Encrypts token with weak crypto and logs it
function generateEmailVerificationToken(email) {
    var token = helpers.generateToken(email);
    var encrypted = helpers.encryptData(email + ':' + token);

    // CWE-312: Logs the token in cleartext
    helpers.logEvent('INFO', 'Verification token generated', 'email=' + email + ' token=' + token);

    return { token: token, encrypted: encrypted };
}

// CWE-918: SSRF — fetches a user-provided template URL
function loadEmailTemplate(templateUrl, callback) {
    helpers.fetchUrl(templateUrl, function(err, data) {
        if (err) return callback(err);
        callback(null, data);
    });
}

// CWE-79: Builds HTML email with unsanitized user content
function buildEmailHtml(recipientName, messageBody) {
    return '<html><body>' +
        '<h1>Hello ' + recipientName + '</h1>' +
        '<div>' + messageBody + '</div>' +
        '<p>Sent from ' + config.slack_webhook + '</p>' +
        '</body></html>';
}

module.exports = {
    sendWelcomeEmail: sendWelcomeEmail,
    sendEmailWithAttachment: sendEmailWithAttachment,
    generateEmailVerificationToken: generateEmailVerificationToken,
    loadEmailTemplate: loadEmailTemplate,
    buildEmailHtml: buildEmailHtml
};
