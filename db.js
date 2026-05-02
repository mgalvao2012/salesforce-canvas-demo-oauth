var sqlite3 = require('sqlite3');
var mkdirp = require('mkdirp');

mkdirp.sync('var/db');

var db = new sqlite3.Database('var/db/todos.db');

// create table once at startup
db.run(`CREATE TABLE IF NOT EXISTS store (key TEXT PRIMARY KEY, value TEXT)`);

module.exports = db;
