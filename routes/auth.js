var qs = require('querystring');
var express = require('express');
var passport = require('passport');
var OpenIDConnectStrategy = require('passport-openidconnect');
var csrf = require('csurf');
var db = require('../db');
var axios = require("axios").default;
var crypto = require('crypto');
var { decodeSignedRequest } = require('../lib/canvas');
var { getAccountName } = require('../lib/salesforce');

var csrfProtection = csrf({ cookie: true });

passport.use(new OpenIDConnectStrategy({
  issuer: 'https://' + process.env['AUTH0_DOMAIN'] + '/',
  authorizationURL: 'https://' + process.env['AUTH0_DOMAIN'] + '/authorize',
  tokenURL: 'https://' + process.env['AUTH0_DOMAIN'] + '/oauth/token',
  userInfoURL: 'https://' + process.env['AUTH0_DOMAIN'] + '/userinfo',
  clientID: process.env['AUTH0_CLIENT_ID'],
  clientSecret: process.env['AUTH0_CLIENT_SECRET'],
  callbackURL: '/callback',
  scope: [ 'profile' ]
},
function verify(issuer, profile, cb) {
  return cb(null, profile);
}));

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.displayName });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

var router = express.Router();

router.get('/login',
  passport.authenticate('openidconnect', {
    prompt: 'login' // forces Auth0 to show the login page even if the user has an active session
  })
);

// PKCE-based login start for mobile (Authorization Code + PKCE)
router.get('/login-mobile-start', function(req, res) {
  // Debug: Check if AUTH0_MOBILE_CLIENT_ID is set
  if (!process.env.AUTH0_MOBILE_CLIENT_ID) {
    console.error('/login-mobile-start - AUTH0_MOBILE_CLIENT_ID not set in environment');
    return res.status(500).send('Server configuration error: AUTH0_MOBILE_CLIENT_ID not set');
  }
  console.log('/login-mobile-start - Using mobile client ID:', process.env.AUTH0_MOBILE_CLIENT_ID.substring(0, 10) + '...');

  // Decode Canvas envelope from query string or session
  let envelope = null;
  if (req.query.signed_request) {
    envelope = decodeSignedRequest(req.query.signed_request, process.env.CANVAS_CONSUMER_SECRET);
  } else if (req.session.envelope) {
    envelope = req.session.envelope;
  }

  if (!envelope) {
    return res.status(400).send('Missing or invalid signed_request');
  }

  // Generate PKCE parameters
  const code_verifier = crypto.randomBytes(32).toString('base64url');
  const code_challenge = crypto.createHash('sha256').update(code_verifier).digest('base64url');
  const state = crypto.randomBytes(32).toString('base64url');

  // Store PKCE state server-side with 10-minute TTL
  const created_at = Math.floor(Date.now() / 1000);
  db.run(
    `INSERT INTO pkce_state (state, code_verifier, envelope, created_at) VALUES (?, ?, ?, ?)`,
    [state, code_verifier, JSON.stringify(envelope), created_at],
    function(err) {
      if (err) {
        console.error('/login-mobile-start - db error: ' + err);
        return res.status(500).send('Failed to initiate login');
      }

      // Redirect to Auth0 /authorize with PKCE parameters
      const authorizeUrl = new URL(`https://${process.env.AUTH0_DOMAIN}/authorize`);
      authorizeUrl.searchParams.set('response_type', 'code');
      authorizeUrl.searchParams.set('client_id', process.env.AUTH0_MOBILE_CLIENT_ID);
      authorizeUrl.searchParams.set('redirect_uri', `${process.env.URL}/callback`);
      authorizeUrl.searchParams.set('scope', 'openid profile email offline_access');
      authorizeUrl.searchParams.set('code_challenge', code_challenge);
      authorizeUrl.searchParams.set('code_challenge_method', 'S256');
      authorizeUrl.searchParams.set('state', state);
      authorizeUrl.searchParams.set('prompt', 'login');  // Force Auth0 to show login form (critical for WKWebView)
      authorizeUrl.searchParams.set('connection', process.env.AUTH0_CONNECTION || 'Username-Password-Authentication');  // Required for Native apps

      console.log('/login-mobile-start - Redirecting to Auth0:', authorizeUrl.toString());
      res.redirect(authorizeUrl.toString());
    }
  );
});

// POST /login-mobile (Resource Owner Password Grant) removed in favor of
// GET /login-mobile-start (Authorization Code + PKCE). See feat/auth0-mfa-pkce-mobile
// for migration rationale: ROPG is deprecated, cannot support MFA properly in WKWebView.

router.get('/callback', async function(req, res, next) {
  const state = req.query.state;
  const code = req.query.code;

  // Check if this is a mobile PKCE callback by looking for state in pkce_state table
  if (state && code) {
    db.get(
      `SELECT code_verifier, envelope, created_at FROM pkce_state WHERE state = ?`,
      [state],
      async function(err, row) {
        if (err) {
          console.error('/callback - PKCE state lookup error: ' + err);
          return res.status(500).send('Authentication failed');
        }

        if (!row) {
          // Not a mobile PKCE flow, fall through to web Passport flow
          return handleWebCallback(req, res, next);
        }

        // Mobile PKCE flow
        const code_verifier = row.code_verifier;
        const envelope = JSON.parse(row.envelope);
        const created_at = row.created_at;
        const now = Math.floor(Date.now() / 1000);

        // Check TTL (10 minutes)
        if (now - created_at > 600) {
          db.run(`DELETE FROM pkce_state WHERE state = ?`, [state]);
          return res.status(400).send('Login expired. Please try again.');
        }

        try {
          // Exchange authorization code for tokens
          const tokenRes = await axios.post(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'authorization_code',
            code: code,
            code_verifier: code_verifier,
            client_id: process.env.AUTH0_MOBILE_CLIENT_ID,
            redirect_uri: `${process.env.URL}/callback`
          });

          const { access_token, refresh_token, id_token } = tokenRes.data;

          // Fetch user info
          const userRes = await axios.get(`https://${process.env.AUTH0_DOMAIN}/userinfo`, {
            headers: { Authorization: `Bearer ${access_token}` }
          });

          const profile = {
            id: userRes.data.sub,
            username: userRes.data.nickname || userRes.data.name,
            displayName: userRes.data.name,
            email: userRes.data.email
          };

          // Store refresh token for silent re-auth
          if (refresh_token) {
            const userEmail = envelope.context.user.email;
            db.run(
              `INSERT OR REPLACE INTO refresh_tokens (email, auth0_user_id, refresh_token, created_at) VALUES (?, ?, ?, ?)`,
              [userEmail, profile.id, refresh_token, now],
              function(err) {
                if (err) console.error('/callback - refresh token store error: ' + err);
              }
            );
          }

          // Also update legacy store table for backwards compatibility
          db.run(
            `INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
            [envelope.context.user.email, profile.id],
            function(err) {
              if (err) console.error('/callback - store update error: ' + err);
            }
          );

          // Delete PKCE state
          db.run(`DELETE FROM pkce_state WHERE state = ?`, [state]);

          // Render app directly (mobile WKWebView doesn't maintain session cookies)
          const csrfProtectionInstance = csrf({ cookie: true });
          csrfProtectionInstance(req, res, async function() {
            try {
              const recordId = envelope.context.environment.record.Id;
              const accountName = await getAccountName(recordId, envelope);
              res.render('index', {
                recordId,
                accountName,
                signedRequestJson: envelope,
                signedRequest: req.query.signed_request || '',
                csrfToken: req.csrfToken()
              });
            } catch (renderErr) {
              console.error('/callback - mobile render error: ' + renderErr);
              res.status(500).send('Login succeeded but failed to load app');
            }
          });
        } catch (tokenErr) {
          console.error('/callback - token exchange error: ' + (tokenErr.response?.data || tokenErr.message));
          db.run(`DELETE FROM pkce_state WHERE state = ?`, [state]);
          res.status(400).send('Authentication failed. Please try again.');
        }
      }
    );
  } else {
    // Web Passport flow
    handleWebCallback(req, res, next);
  }
});

// Web callback handler (existing Passport flow)
function handleWebCallback(req, res, next) {
  // Capture envelope before Passport regenerates the session (session fixation prevention).
  const savedEnvelope = req.session.envelope;

  passport.authenticate('openidconnect', function(err, user) {
    if (err) return next(err);
    if (!user) return res.redirect('/login');

    req.logIn(user, function(err) {
      if (err) return next(err);

      // Restore envelope into the new session so downstream routes can use it.
      req.session.envelope = savedEnvelope;
      req.session.save(function(err) {
        if (err) return next(err);
        res.redirect('/auth-success');
      });
    });
  })(req, res, next);
}

router.get('/auth-success', function(req, res) {
  const envelope = req.session.envelope;
  if (!req.user || !envelope) {
    return res.status(401).send('Session expired. Please reload the app.');
  }
  db.run(`INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
    [envelope.context.user.email, req.user.id], function(err) {
      if (err) console.error('Error storing email in database: ' + err);
    });
  res.render('auth-success');
});

router.post('/logout', function(req, res, next) {
  const signedRequest = req.body.signed_request || null;

  // Decode envelope to get user email and delete refresh token
  let envelope = null;
  if (signedRequest) {
    envelope = decodeSignedRequest(signedRequest, process.env.CANVAS_CONSUMER_SECRET);
    if (envelope && envelope.context.user.email) {
      db.run(`DELETE FROM refresh_tokens WHERE email = ?`, [envelope.context.user.email], function(err) {
        if (err) console.error('/logout - refresh token delete error: ' + err);
      });
    }
  }

  axios.get('https://' + process.env['AUTH0_DOMAIN'] + '/v2/logout')
    .then(() => {
      res.render('login', { signedRequest: signedRequest });
    })
    .catch(err => {
      console.error('Error logging out of Auth0: ' + err);
      res.render('login', { signedRequest: signedRequest });
    });
});

router.get('/logout', function(req, res, next) {
  const signedRequest = req.body.signed_request || null;

  // Delete refresh token from session envelope if available
  if (req.session.envelope && req.session.envelope.context.user.email) {
    db.run(`DELETE FROM refresh_tokens WHERE email = ?`, [req.session.envelope.context.user.email], function(err) {
      if (err) console.error('/logout - refresh token delete error: ' + err);
    });
  }

  axios.get('https://' + process.env['AUTH0_DOMAIN'] + '/v2/logout')
    .then(() => {
      res.render('login', { signedRequest: signedRequest });
    })
    .catch(err => {
      console.error('Error logging out of Auth0: ' + err);
      res.send('Not logged out');
    });
});

module.exports = router;
