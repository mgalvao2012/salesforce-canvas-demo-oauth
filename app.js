require("dotenv").config();
var express = require("express"),
	bodyParser = require("body-parser"),
	path = require("path"),
	axios = require("axios").default;

var app = express();
var crypto = require("crypto");
const consumerSecretApp = process.env.CANVAS_CONSUMER_SECRET;
const PORT = process.env.PORT;

global.envelope = ""; // salesforce instance information

app.use(express.static(path.join(__dirname, "views")));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded());
app.use(bodyParser.json());

app.get("/", function (req, res) {
	res.render("login");
});

app.get("/callback", function (req, res) {
	console.log(req.query);
	res.render("callback");
});

app.post("/", async function (req, res) {
	var bodyArray = req.body.signed_request.split(".");
	var consumerSecret = bodyArray[0];
	var encoded_envelope = bodyArray[1];

	var check = crypto
		.createHmac("sha256", consumerSecretApp)
		.update(encoded_envelope)
		.digest("base64");

	if (check === consumerSecret) {
		const envelope = JSON.parse(Buffer.from(encoded_envelope, "base64").toString("ascii"));
		console.log("got the session object:");
		console.log(req.body.signed_request);
		global.envelope = envelope;
		console.log(global.envelope);
		res.render("index", {
			recordId: envelope.context.environment.record.Id,
			accountName: await getAccountName(envelope.context.environment.record.Id),
			signedRequestJson: envelope,
		});
	} else {
		res.send("authentication failed");
	}
});

app.post("/updateAccount", async function (req, res) {
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

app.listen(PORT, function () {
	console.log("server is listening!!!");
});
