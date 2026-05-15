var qs = require('querystring');
var express = require('express');
var passport = require('passport');
var OpenIDConnectStrategy = require('passport-openidconnect');
var csrf = require('csurf');
var db = require('../db');
var axios = require("axios").default;
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

// Helper: render the app to HTML and return as JSON for AJAX-based mobile flow
async function renderAppWithTokens(req, res, envelope, tokens) {
  const { access_token, refresh_token } = tokens;

  try {
    // Fetch user info from Auth0
    const userRes = await axios.get(`https://${process.env.AUTH0_DOMAIN}/userinfo`, {
      headers: { Authorization: `Bearer ${access_token}` }
    });

    const profile = {
      id: userRes.data.sub,
      username: userRes.data.nickname || userRes.data.name,
      displayName: userRes.data.name,
      email: userRes.data.email
    };

    const userEmail = envelope.context.user.email;
    const now = Math.floor(Date.now() / 1000);

    // Store refresh token for silent re-auth
    if (refresh_token) {
      db.run(
        `INSERT OR REPLACE INTO refresh_tokens (email, auth0_user_id, refresh_token, created_at) VALUES (?, ?, ?, ?)`,
        [userEmail, profile.id, refresh_token, now],
        function(err) {
          if (err) console.error('renderAppWithTokens - refresh token store error: ' + err);
        }
      );
    }

    // Update legacy store table
    db.run(
      `INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
      [userEmail, profile.id],
      function(err) {
        if (err) console.error('renderAppWithTokens - store update error: ' + err);
      }
    );

    // Render index.ejs to HTML string and return as JSON
    const csrfProtectionInstance = csrf({ cookie: true });
    csrfProtectionInstance(req, res, async function() {
      try {
        const recordId = envelope.context.environment.record.Id;
        const accountName = await getAccountName(recordId, envelope);
        res.render('index', {
          recordId,
          accountName,
          signedRequestJson: envelope,
          signedRequest: req.body.signed_request || '',
          csrfToken: req.csrfToken()
        }, function(err, html) {
          if (err) {
            console.error('renderAppWithTokens - render error:', err);
            return res.status(500).json({ error: 'Failed to render app' });
          }
          res.json({ success: true, html: html });
        });
      } catch (renderErr) {
        console.error('renderAppWithTokens - error:', renderErr);
        res.status(500).json({ error: 'Login succeeded but failed to load app' });
      }
    });
  } catch (err) {
    console.error('renderAppWithTokens - userinfo error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch user info' });
  }
}

// POST /login-mobile - First step of mobile login: email + password
// Returns mfa_required if MFA is needed (always, since policy is "Always")
router.post('/login-mobile', async function(req, res) {
  // Decode Canvas envelope from request body
  let envelope = null;
  if (req.body.signed_request) {
    envelope = decodeSignedRequest(req.body.signed_request, process.env.CANVAS_CONSUMER_SECRET);
  }
  if (!envelope) {
    return res.status(400).json({ error: 'Missing or invalid signed_request' });
  }

  try {
    // Call Auth0 /oauth/token with password-realm grant
    // audience=https://{domain}/mfa/ is required to enable MFA grant types
    const tokenRes = await axios.post(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
      username: req.body.email,
      password: req.body.password,
      realm: process.env.AUTH0_CONNECTION || 'Username-Password-Authentication',
      scope: 'openid profile email offline_access',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      audience: `https://${process.env.AUTH0_DOMAIN}/mfa/`
    });

    // Login succeeded without MFA (only if MFA policy is not "Always")
    return await renderAppWithTokens(req, res, envelope, tokenRes.data);

  } catch (err) {
    const errorData = err.response?.data || {};

    // Check if Auth0 is asking for MFA
    if (errorData.error === 'mfa_required') {
      console.log('/login-mobile - MFA required for user:', req.body.email);
      return res.json({
        mfa_required: true,
        mfa_token: errorData.mfa_token
      });
    }

    // Other errors (invalid credentials, etc.)
    console.error('/login-mobile - auth error:', errorData.error_description || err.message);
    return res.status(401).json({ error: errorData.error_description || 'Invalid email or password' });
  }
});

// POST /login-mobile-mfa - Second step of mobile login: TOTP code
router.post('/login-mobile-mfa', async function(req, res) {
  // Decode Canvas envelope from request body
  let envelope = null;
  if (req.body.signed_request) {
    envelope = decodeSignedRequest(req.body.signed_request, process.env.CANVAS_CONSUMER_SECRET);
  }
  if (!envelope) {
    return res.status(400).json({ error: 'Missing or invalid signed_request' });
  }

  if (!req.body.mfa_token || !req.body.otp) {
    return res.status(400).json({ error: 'Missing mfa_token or otp' });
  }

  try {
    // Exchange mfa_token + otp for access_token
    const tokenRes = await axios.post(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      grant_type: 'http://auth0.com/oauth/grant-type/mfa-otp',
      mfa_token: req.body.mfa_token,
      otp: req.body.otp,
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET
    });

    return await renderAppWithTokens(req, res, envelope, tokenRes.data);
  } catch (err) {
    const errorData = err.response?.data || {};
    console.error('/login-mobile-mfa - error:', errorData.error_description || err.message);

    if (errorData.error === 'invalid_grant' && errorData.error_description?.includes('expired')) {
      return res.status(401).json({ error: 'MFA session expired. Please log in again.', expired: true });
    }

    return res.status(401).json({ error: errorData.error_description || 'Invalid TOTP code' });
  }
});

router.get('/callback', function(req, res, next) {
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
});

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
