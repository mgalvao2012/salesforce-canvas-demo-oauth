var qs = require('querystring');
var express = require('express');
var passport = require('passport');
var OpenIDConnectStrategy = require('passport-openidconnect');
var db = require('../db');
var axios = require("axios").default;

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

    const savedEnvelope = req.session.envelope;

    req.logIn({ id: profile.id, username: profile.username, name: profile.displayName }, function(err) {
      if (err) {
        console.log('/login-mobile - logIn error: ' + err);
        return res.render('login', { error: 'Login failed. Please try again.' });
      }

      // After successful login, we need to restore the envelope in the session if it was there before, since logging in may have cleared it. This ensures that we can still access the envelope data after logging in, which is necessary for the app to function properly. --- IGNORE ---
      req.session.envelope = savedEnvelope;
      req.session.save(function(saveErr) {
        if (saveErr) console.log('/login-mobile - session save error: ' + saveErr);

        db.run(`INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
          [req.body.email, profile.id], function(err) {
            if (err) console.log('/login-mobile - db error: ' + err);
          });
        res.redirect('/');
      });
    });
  } catch (err) {
    const msg = err.response && err.response.data && err.response.data.error_description
      ? err.response.data.error_description
      : 'Invalid email or password';
    console.log('/login-mobile - auth error: ' + msg);
    res.render('login', { error: msg });
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
