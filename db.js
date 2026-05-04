var sqlite3 = require('sqlite3');
var mkdirp = require('mkdirp');

mkdirp.sync('var/db');

// open the database
var db = new sqlite3.Database('var/db/store.db');

// create table once at startup
db.run(`CREATE TABLE IF NOT EXISTS store (key TEXT PRIMARY KEY, value TEXT)`);

module.exports = db;
