var qs = require('querystring');
var crypto = require('crypto');
var express = require('express');
var passport = require('passport');
var OpenIDConnectStrategy = require('passport-openidconnect');
var csrf = require('csurf');
var db = require('../db');
var axios = require("axios").default;

var csrfProtection = csrf({ cookie: true });

async function getAccountName(recordId, envelope) {
  const url = `${envelope.client.instanceUrl}${envelope.context.links.sobjectUrl}Account/${recordId}?fields=Name`;
  const headers = {
    Authorization: `Bearer ${envelope.client.oauthToken}`,
    'Content-Type': 'application/json',
  };
  const response = await axios.get(url, { headers });
  return response.data.Name;
}

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
  console.log('/login-mobile - signed_request present: ' + !!req.body.signed_request);
  console.log('/login-mobile - signed_request length: ' + (req.body.signed_request ? req.body.signed_request.length : 0));
  let envelope = null;
  if (req.body.signed_request) {
    try {
      const bodyArray = req.body.signed_request.split('.');
      const consumerSecret = bodyArray[0];
      const encoded_envelope = bodyArray[1];
      console.log('/login-mobile - CANVAS_CONSUMER_SECRET set: ' + !!process.env.CANVAS_CONSUMER_SECRET);
      const check = crypto
        .createHmac('sha256', process.env.CANVAS_CONSUMER_SECRET)
        .update(encoded_envelope)
        .digest('base64');
      console.log('/login-mobile - HMAC match: ' + (check === consumerSecret));
      if (check === consumerSecret) {
        envelope = JSON.parse(Buffer.from(encoded_envelope, 'base64').toString('ascii'));
        console.log('/login-mobile - envelope decoded, user email: ' + envelope?.context?.user?.email);
      } else {
        console.log('/login-mobile - signed_request HMAC mismatch');
      }
    } catch (e) {
      console.log('/login-mobile - signed_request decode error: ' + e);
    }
  } else {
    console.log('/login-mobile - no signed_request in body, keys: ' + Object.keys(req.body).join(', '));
  }

  try {
    const tokenRes = await axios.post('https://' + process.env['AUTH0_DOMAIN'] + '/oauth/token', {
      grant_type: 'password',
      username: req.body.email,
      password: req.body.password,
      scope: 'openid profile',
      client_id: process.env['AUTH0_CLIENT_ID'],
      client_secret: process.env['AUTH0_CLIENT_SECRET'],
      connection: 'Username-Password-Authentication'
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
        if (err) console.log('/login-mobile - db error: ' + err);
      });

    if (!envelope) {
      console.log('/login-mobile - no envelope, cannot render app');
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
        console.log('/login-mobile - render error: ' + renderErr);
        res.render('login', { error: 'Login succeeded but failed to load app.', signedRequest: req.body.signed_request });
      }
    });
  } catch (err) {
    const msg = err.response && err.response.data && err.response.data.error_description
      ? err.response.data.error_description
      : 'Invalid email or password';
    console.log('/login-mobile - auth error: ' + msg);
    res.render('login', { error: msg, signedRequest: req.body.signed_request });
  }
});

router.get('/callback', passport.authenticate('openidconnect', {
  successRedirect: '/auth-success',
  failureRedirect: '/login'
}));

router.get('/auth-success', function(req, res) {
  console.log('/auth-success - req.session: ' + JSON.stringify(req.session));
  db.run(`INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
    [req.session.envelope.context.user.email, req.session.passport.user.id], function(err) {
      if (err) {
        console.log('Error storing email in database: ' + err);
      }
    });

  res.render('auth-success');
});

router.get('/logout', function(req, res, next) {
  /*
  db.run(`DELETE FROM store WHERE key = ?`, [req.session.envelope.context.user.email, function(err) {
    if (err) {
      console.log('Error deleting email from database: ' + err);
    }
  });
  */
  // Log out of Auth0 as well by calling the logout endpoint with the appropriate parameters
  axios.get('https://' + process.env['AUTH0_DOMAIN'] + '/v2/logout')
    .then(() => {
      console.log('Logged out of Auth0 successfully');
      res.render('login');
    })
    .catch(err => {
      console.log('Error logging out of Auth0: ' + err);
      res.send('Not logged out');
    });

});

module.exports = router;
