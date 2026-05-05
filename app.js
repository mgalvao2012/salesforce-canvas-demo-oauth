require("dotenv").config();

var axios = require("axios").default;
var bodyParser = require("body-parser");
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var csrf = require('csurf');
var passport = require('passport');
var logger = require('morgan');
const https = require('https');
const fs    = require('fs');

// pass the session to the connect sqlite3 module
// allowing it to inherit from session.Store
var SQLiteStore = require('connect-sqlite3')(session);
var db = require('./db');
var { decodeSignedRequest } = require('./lib/canvas');
var { getAccountName } = require('./lib/salesforce');

var indexRouter = require('./routes/index');
var authRouter = require('./routes/auth');

var app = express();

// Heroku requires secure cookies, but we can only set that if we're actually running on Heroku (or another environment with a similar requirement)
if (process.env.DYNO) {
  app.set('trust proxy', 1);
}
const consumerSecretApp = process.env.CANVAS_CONSUMER_SECRET;
const PORT = process.env.PORT;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ limit: '10kb' }));
app.use(bodyParser.json({ limit: '10kb' }));
app.locals.pluralize = require('pluralize');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false, // don't save session if unmodified
  saveUninitialized: false, // don't create session until something stored
  store: new SQLiteStore({ db: 'sessions.db', dir: 'var/db' }),
  cookie: {
    sameSite: 'none', // required for cross-site iframe (Salesforce Canvas)
    secure: true      // required with sameSite=none; works via ngrok/Heroku (trust proxy above)
  }
}));
var csrfProtection = csrf({ cookie: true });
app.use(passport.initialize());
app.use(passport.authenticate('session'));
app.use(function(req, res, next) {
  var msgs = req.session.messages || [];
  res.locals.messages = msgs;
  res.locals.hasMessages = !! msgs.length;
  req.session.messages = [];
  next();
});

// get information about the device from the user-agent header and
// make it available in the templates for conditional rendering based
// on whether the user is on mobile or desktop
app.use(function(req, res, next) {
  const ua = req.headers['user-agent'];
  res.locals.isMobile = /Mobile|Android|iPhone|iPad/i.test(ua);
  res.locals.userAgent = ua;
  res.locals.clientId = process.env.AUTH0_CLIENT_ID;
  res.locals.domain = process.env.AUTH0_DOMAIN;
  res.locals.callbackUrl = process.env.URL + '/callback';
  res.locals.salesforceDomain = process.env.SALESFORCE_DOMAIN;
  next();
});

app.use('/', indexRouter);
app.use('/', authRouter);

app.get("/callback_sfdc", function (req, res) {
	res.render("callback");
});

app.post("/", async function (req, res) {
	console.log('app POST / - received signed_request: ' + req.body.signed_request);
	const envelope = decodeSignedRequest(req.body.signed_request, consumerSecretApp);

	if (envelope) {
		req.session.envelope = envelope;

		db.get(`SELECT value FROM store WHERE key = ?`, [envelope.context.user.email], async (err, row) => {
			if (err) {
				console.error('app POST / - db error: ' + err);
				return res.render('login', { signedRequest: req.body.signed_request });
			}
			
			const userId = row ? row.value : null;
			if (!userId) {
				res.render('login', { signedRequest: req.body.signed_request });
			} else {
				// Render the app directly — no redirect — so the mobile WKWebView does not
				// need to carry a session cookie across requests.
				try {
					const csrfProtectionInstance = csrf({ cookie: true });
					csrfProtectionInstance(req, res, async function() {
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
							console.error('app POST / - render error: ' + renderErr);
							res.render('login', { signedRequest: req.body.signed_request });
						}
					});
				} catch (e) {
					console.error('app POST / - csrf error: ' + e);
					res.render('login', { signedRequest: req.body.signed_request });
				}
			}
		});

	} else {
		res.status(401).send("authentication failed");
	}
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

if (process.env.LOCAL_HTTPS === 'true') {
  const sslOptions = {
    key:  fs.readFileSync('./certs/localhost-key.pem'),
    cert: fs.readFileSync('./certs/localhost.pem'),
  };
  https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`Server listening on https://localhost:${PORT}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}
