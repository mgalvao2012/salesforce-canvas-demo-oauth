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

router.get('/callback', passport.authenticate('openidconnect', {
  successRedirect: '/auth-success',
  failureRedirect: '/login'
}));

router.get('/auth-success', function(req, res) {
  console.log('/auth-success - req.session.userId: ' + req.session.userId);
  console.log('/auth-success - global.envelope.userId: ' + global.envelope.userId);

  db.run(`INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)`,
    [global.envelope.userId, req.session.passport.user.id], function(err) {
      if (err) {
        console.log('Error storing userId in database: ' + err);
      }
    });

  res.render('auth-success');
});

router.get('/logout', function(req, res, next) {
  console.log('/logout - req.session.userId: ' + req.session.userId);
  console.log('/logout - global.envelope.userId: ' + global.envelope.userId);
  db.run(`DELETE FROM store WHERE key = ?`, [global.envelope.userId], function(err) {
    if (err) {
      console.log('Error deleting userId from database: ' + err);
    }
  });
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
