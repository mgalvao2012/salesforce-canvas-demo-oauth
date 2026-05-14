var sqlite3 = require('sqlite3');
var mkdirp = require('mkdirp');

mkdirp.sync('var/db');

// open the database
var db = new sqlite3.Database('var/db/store.db');

// create table once at startup
db.run(`CREATE TABLE IF NOT EXISTS store (key TEXT PRIMARY KEY, value TEXT)`);

// PKCE state table for mobile Authorization Code flow
// state = random opaque identifier used in OAuth redirect
// code_verifier = PKCE verifier (SHA-256 hashed to code_challenge at /authorize)
// envelope = serialized Canvas signed_request envelope
// created_at = Unix timestamp for TTL cleanup
db.run(`CREATE TABLE IF NOT EXISTS pkce_state (
  state TEXT PRIMARY KEY,
  code_verifier TEXT NOT NULL,
  envelope TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`);

// Refresh token storage for silent re-auth on mobile
// email = Canvas user email (from envelope.context.user.email)
// auth0_user_id = Auth0 sub claim
// refresh_token = Auth0 offline_access refresh token (rotated on each use)
// created_at = Unix timestamp for absolute lifetime enforcement
db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
  email TEXT PRIMARY KEY,
  auth0_user_id TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`);

module.exports = db;
