var express = require('express');
var axios = require('axios').default;
var csrf = require('csurf');
var csrfProtection = csrf({ cookie: true });
var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
var db = require('../db');
var { decodeSignedRequest } = require('../lib/canvas');
var { getAccountName } = require('../lib/salesforce');

var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  const envelope = req.session.envelope;
  if (!envelope || !envelope.context || !envelope.context.user || !envelope.context.user.email) {
    res.render('login');
    return;
  }

  db.get(`SELECT value FROM store WHERE key = ?`, [envelope.context.user.email], (err, row) => {
    if (err) {
      console.error('/ - db error: ' + err);
      return res.render('login');
    }
    res.locals.filter = null;
    csrfProtection(req, res, async function() {
      res.render("index", {
        recordId: envelope.context.environment.record.Id,
        accountName: await getAccountName(envelope.context.environment.record.Id, envelope),
        signedRequestJson: envelope,
        csrfToken: req.csrfToken(),
      });
    });
  });
});

router.post("/updateAccount", async function (req, res) {
  let recordId = req.body.recordId;
  let accountName = req.body.accountName;
  let envelope = req.session.envelope;

  // Mobile Canvas flow: session cookie not maintained by WKWebView,
  // re-decode envelope from signed_request carried in the form body.
  if (!envelope && req.body.signed_request) {
    envelope = decodeSignedRequest(req.body.signed_request, process.env.CANVAS_CONSUMER_SECRET);
    if (!envelope) {
      console.error('/updateAccount - signed_request HMAC mismatch or decode error');
    }
  }

  if (!envelope) {
    return res.status(401).send('Unauthorized');
  }

  const instanceUrl = envelope.client.instanceUrl;
  const sobjectUrl = envelope.context.links.sobjectUrl;
  const oauthToken = envelope.client.oauthToken;
  const url = `${instanceUrl}${sobjectUrl}Account/${recordId}`;
  const headers = {
    Authorization: `Bearer ${oauthToken}`,
    "Content-Type": "application/json",
  };
  try {
    await axios.patch(url, { name: accountName }, { headers });
  } catch (error) {
    console.error("Error updating account:", error.response?.data || error.message);
    throw error;
  }
  res.send("account name updated!");
});

module.exports = router;
