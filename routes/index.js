var express = require('express');
var axios = require("axios").default;
var csrf = require('csurf');
var csrfProtection = csrf();
var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
var db = require('../db');

var ensureLoggedIn = ensureLogIn();
var app = express();
var router = express.Router();

async function getAccountName(recordId, envelope) {
  let instanceUrl = envelope.client.instanceUrl;
  let sobjectUrl = envelope.context.links.sobjectUrl;
  let oauthToken = envelope.client.oauthToken;
  const url = `${instanceUrl}${sobjectUrl}Account/${recordId}?fields=Name`;
  const headers = {
    Authorization: `Bearer ${oauthToken}`,
    "Content-Type": "application/json",
  };
  try {
    const response = await axios.get(url, { headers });
    console.log("account get data successfully:", response.data);
    return response.data.Name;
  } catch (error) {
    console.error("Error getting account:", error.response?.data || error.message);
    throw error;
    return "";
  }
}

/* GET home page. */
router.get('/', function(req, res, next) {
  console.log('/ - req.session: ' + JSON.stringify(req.session));
  const envelope = req.session.envelope;
  if (!envelope || !envelope.context || !envelope.context.user || !envelope.context.user.email) {
    console.log('User email is not available in the envelope. Redirecting to login page.');
    res.render('login');
    return;
  }
  
  console.log('/ - req.session.envelope: ' + JSON.stringify(envelope));
  console.log('/ - req.session.envelope.context.user.email: ' + envelope.context.user.email);

  db.get(`SELECT value FROM store WHERE key = ?`, [envelope.context.user.email], (err, row) => {
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
  const envelope = req.session.envelope;
  let instanceUrl = envelope.client.instanceUrl;
  let sobjectUrl = envelope.context.links.sobjectUrl;
  let oauthToken = envelope.client.oauthToken;
  const url = `${instanceUrl}${sobjectUrl}Account/${recordId}`;
  const headers = {
    Authorization: `Bearer ${oauthToken}`,
    "Content-Type": "application/json",
  };
  try {
    const response = await axios.patch(url, { name: accountName }, { headers });
    console.log("account updated successfully:", response.data);
  } catch (error) {
    console.error("Error updating account:", error.response?.data || error.message);
    throw error;
  }
  res.send("account name updated!");
});

module.exports = router;
