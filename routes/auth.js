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

router.post('/login-mobile', async function(req, res) {
  // Decode the Canvas envelope from the signed_request posted by the login form.
  // We cannot rely on the session here: the initial Canvas POST "/" is made by
  // Salesforce infrastructure (not the browser), so its Set-Cookie never reaches
  // the WKWebView cookie jar. The envelope travels via the hidden form field instead.
  let envelope = null;
  if (req.body.signed_request) {
    envelope = decodeSignedRequest(req.body.signed_request, process.env.CANVAS_CONSUMER_SECRET);
    if (!envelope) {
      console.error('/login-mobile - signed_request HMAC mismatch or decode error');
    }
  }

  try {
    const tokenRes = await axios.post('https://' + process.env['AUTH0_DOMAIN'] + '/oauth/token', {
      grant_type: 'password',
      username: req.body.email,
      password: req.body.password,
      scope: 'openid profile',
      client_id: process.env['AUTH0_CLIENT_ID'],
      client_secret: process.env['AUTH0_CLIENT_SECRET'],
      connection: process.env.AUTH0_CONNECTION || 'Username-Password-Authentication'
    });

    const userRes = await axios.get('https://' + process.env['AUTH0_DOMAIN'] + '/userinfo', {
      headers: { Authorization: 'Bearer ' + tokenRes.data.access_token }
    });

    const profile = {
      id: userRes.data.sub,
      username: userRes.data.nickname || userRes.data.name,
      displayName: userRes.data.name
    };

    db.run(`INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
      [req.body.email, profile.id], function(err) {
        if (err) console.error('/login-mobile - db error: ' + err);
      });

    if (!envelope) {
      return res.render('login', { error: 'Session expired. Please reload the app.', signedRequest: req.body.signed_request });
    }

    // Render the app directly — no redirect needed.
    // The Salesforce Mobile WKWebView does not maintain session cookies across requests,
    // so we never redirect through GET "/" for the mobile flow.
    csrfProtection(req, res, async function() {
      try {
        const recordId = envelope.context.environment.record.Id;
        const accountName = await getAccountName(recordId, envelope);
        res.render('index', {
          recordId,
          accountName,
          signedRequestJson: envelope,
          signedRequest: req.body.signed_request,
          csrfToken: req.csrfToken(),
        });
      } catch (renderErr) {
        console.error('/login-mobile - render error: ' + renderErr);
        res.render('login', { error: 'Login succeeded but failed to load app.', signedRequest: req.body.signed_request });
      }
    });
  } catch (err) {
    console.error('/login-mobile - auth error: ' + (err.response?.data?.error || err.message));
    res.render('login', { error: 'Invalid email or password', signedRequest: req.body.signed_request });
  }
});

router.get('/callback', passport.authenticate('openidconnect', {
  successRedirect: '/auth-success',
  failureRedirect: '/login'
}));

router.get('/auth-success', function(req, res) {
  if (!req.session.envelope) {
    console.error('/auth-success - no envelope in session');
    return res.render('home');
  }
  db.run(`INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
    [req.session.envelope.context.user.email, req.session.passport.user.id], function(err) {
      if (err) {
        console.error('Error storing email in database: ' + err);
      }
    });

  res.render('auth-success');
});

router.post('/logout', function(req, res, next) {
  const signedRequest = req.body.signed_request || null;
  axios.get('https://' + process.env['AUTH0_DOMAIN'] + '/v2/logout')
    .then(() => {
      res.render('login', { signedRequest });
    })
    .catch(err => {
      console.error('Error logging out of Auth0: ' + err);
      res.render('login', { signedRequest });
    });
});

router.get('/logout', function(req, res, next) {
  axios.get('https://' + process.env['AUTH0_DOMAIN'] + '/v2/logout')
    .then(() => {
      res.render('login');
    })
    .catch(err => {
      console.error('Error logging out of Auth0: ' + err);
      res.send('Not logged out');
    });
});

module.exports = router;
