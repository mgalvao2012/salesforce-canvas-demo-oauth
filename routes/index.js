var express = require('express');
var axios = require("axios").default;
var csrf = require('csurf');
var csrfProtection = csrf();
var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
var db = require('../db');

var ensureLoggedIn = ensureLogIn();
var app = express();
var router = express.Router();

async function getAccountName(recordId) {
  let instanceUrl = global.envelope.client.instanceUrl;
  let sobjectUrl = global.envelope.context.links.sobjectUrl;
  let oauthToken = global.envelope.client.oauthToken;
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
  console.log('global.envelope.userId: ' + global.envelope.userId);

  db.get(`SELECT value FROM store WHERE key = ?`, [global.envelope.userId], (err, row) => {
    console.log('db get error: ' + err);
    const userId = row ? row.value : null;
    console.log('db get userId: ' + userId);

    if (!userId) {
      return res.render('login');
    }
    res.locals.filter = null;
    
    csrfProtection(req, res, async function() {
			res.render("index", {
				recordId: global.envelope.context.environment.record.Id,
				accountName: await getAccountName(global.envelope.context.environment.record.Id),
				signedRequestJson: global.envelope,
				csrfToken: req.csrfToken(),
			});
		});
  });
});

router.post("/updateAccount", async function (req, res) {
  let recordId = req.body.recordId;
  let accountName = req.body.accountName;
  let instanceUrl = global.envelope.client.instanceUrl;
  let sobjectUrl = global.envelope.context.links.sobjectUrl;
  let oauthToken = global.envelope.client.oauthToken;
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
