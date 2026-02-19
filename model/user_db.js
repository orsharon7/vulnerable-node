// User database model — ALL queries use string concatenation
// Called from: routes/users.js, routes/api.js
// Also calls: model/helpers.js for SQL building
// This creates 3-file taint chains: route → user_db → helpers → SQL

var config = require('../config');
var helpers = require('./helpers');
var pgp = require('pg-promise')();
var db = pgp(config.db.connectionString);

// CWE-89: SQL injection — username and password go straight into query
// Called from: routes/users.js (/users/login)
function authenticate(username, passwordHash) {
    var q = "SELECT * FROM users WHERE name = '" + username + "' AND password = '" + passwordHash + "'";
    return db.one(q);
}

// CWE-89: All fields concatenated into INSERT
// Called from: routes/users.js (/users/register), routes/api.js (/api/admin/users)
function createUser(username, passwordHash, email, role) {
    var q = "INSERT INTO users(name, password, email, role) VALUES('" +
        username + "', '" + passwordHash + "', '" + email + "', '" + role + "') RETURNING *";
    return db.one(q);
}

// CWE-89: User-controlled id in WHERE clause
// Called from: routes/users.js (/users/profile)
function findUser(userId) {
    var q = "SELECT * FROM users WHERE id = '" + userId + "'";
    return db.one(q);
}

// CWE-89: User-controlled name in WHERE clause
// Called from: routes/users.js (/users/me)
function findByName(name) {
    var q = "SELECT * FROM users WHERE name = '" + name + "'";
    return db.one(q);
}

// CWE-89: All profile fields concatenated into UPDATE
// Called from: routes/users.js (/users/profile/update)
function updateProfile(username, profileData) {
    var setClauses = [];
    for (var key in profileData) {
        setClauses.push(key + " = '" + profileData[key] + "'");
    }
    var q = "UPDATE users SET " + setClauses.join(', ') + " WHERE name = '" + username + "'";
    return db.none(q);
}

// CWE-89: Using helpers.buildWhereClause for SQL (taint through helpers.js)
// Called from: routes/users.js (/users/search) via helpers.buildQuery
function findUsers(filters) {
    var whereClause = helpers.buildWhereClause(filters);
    var q = "SELECT * FROM users" + whereClause;
    return db.many(q);
}

// CWE-89: Arbitrary SQL execution — called from routes/api.js
function rawQuery(query) {
    return db.any(query);
}

// CWE-89: User-controlled id in DELETE
// Called from: routes/api.js (/api/admin/users/:id)
function deleteUser(userId) {
    var q = "DELETE FROM users WHERE id = '" + userId + "'";
    return db.none(q);
}

// CWE-89: JSON preferences stored without parameterization
// Called from: routes/users.js (/users/preferences)
function savePreferences(username, prefs) {
    var q = "UPDATE users SET preferences = '" + JSON.stringify(prefs) + "' WHERE name = '" + username + "'";
    return db.none(q);
}

// CWE-89: Search across multiple tables with user input
function searchAll(searchTerm) {
    var q = "SELECT * FROM users WHERE name ILIKE '%" + searchTerm + "%' " +
            "UNION SELECT * FROM users WHERE email ILIKE '%" + searchTerm + "%'";
    return db.many(q);
}

// CWE-89 + CWE-327: Stores encrypted data (weak encryption from helpers.js)
function storeEncryptedData(userId, data) {
    var encrypted = helpers.encryptData(data);
    var q = "UPDATE users SET encrypted_data = '" + encrypted + "' WHERE id = '" + userId + "'";
    return db.none(q);
}

module.exports = {
    authenticate: authenticate,
    createUser: createUser,
    findUser: findUser,
    findByName: findByName,
    updateProfile: updateProfile,
    findUsers: findUsers,
    rawQuery: rawQuery,
    deleteUser: deleteUser,
    savePreferences: savePreferences,
    searchAll: searchAll,
    storeEncryptedData: storeEncryptedData
};
