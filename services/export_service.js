// Export service — generates reports with user-controlled data
// Called from: routes/api.js — creates multi-file taint flows

var helpers = require('../model/helpers');
var userDb = require('../model/user_db');
var exec = require('child_process').exec;
var fs = require('fs');
var path = require('path');

// CWE-78: Command injection — user controls report format parameter
// Taint: format → exec('wkhtmltopdf ...')
function generateReport(format, title, data, callback) {
    var tmpFile = '/tmp/report_' + Date.now() + '.' + format;
    var content = '<html><head><title>' + title + '</title></head><body>' + JSON.stringify(data) + '</body></html>';

    var htmlFile = tmpFile + '.html';
    fs.writeFileSync(htmlFile, content);

    // CWE-78: format is user-controlled
    var cmd = 'wkhtmlto' + format + ' ' + htmlFile + ' ' + tmpFile;
    exec(cmd, function(err) {
        callback(err, tmpFile);
    });
}

// CWE-89 + CWE-22: Exports query results to a user-controlled file path
function exportQueryToFile(table, filters, outputPath, callback) {
    // Taint: table + filters → helpers.buildQuery → SQL injection
    var query = helpers.buildQuery(table, filters);

    userDb.rawQuery(query)
        .then(function(data) {
            // Taint: outputPath → fs.writeFileSync (path traversal)
            fs.writeFileSync(outputPath, JSON.stringify(data, null, 2));
            helpers.logEvent('INFO', 'Export completed', 'file=' + outputPath + ' rows=' + data.length);
            callback(null, outputPath);
        })
        .catch(function(err) {
            callback(err);
        });
}

// CWE-502: Imports data from a serialized format
function importFromFile(filePath, callback) {
    // Taint: filePath → fs.readFile (path traversal)
    helpers.readUserFile(filePath, function(err, data) {
        if (err) return callback(err);

        // Taint: file content → helpers.deserializeData → node-serialize
        var obj = helpers.deserializeData(data);
        callback(null, obj);
    });
}

// CWE-22: User-controlled template path
function loadTemplate(templateName) {
    var templatePath = helpers.resolveFilePath(path.join(__dirname, '..', 'views'), templateName);
    return fs.readFileSync(templatePath, 'utf8');
}

module.exports = {
    generateReport: generateReport,
    exportQueryToFile: exportQueryToFile,
    importFromFile: importFromFile,
    loadTemplate: loadTemplate
};
