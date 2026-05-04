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

var indexRouter = require('./routes/index');
var authRouter = require('./routes/auth');

var app = express();

// Heroku requires secure cookies, but we can only set that if we're actually running on Heroku (or another environment with a similar requirement)
if (process.env.DYNO) {
  app.set('trust proxy', 1);
}
var crypto = require("crypto");
const consumerSecretApp = process.env.CANVAS_CONSUMER_SECRET;
const PORT = process.env.PORT;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded());
app.use(bodyParser.json());
app.locals.pluralize = require('pluralize');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'keyboard cat',
  resave: false, // don't save session if unmodified
  saveUninitialized: false, // don't create session until something stored
  store: new SQLiteStore({ db: 'sessions.db', dir: 'var/db' }),
  cookie: {
    sameSite: 'none', // required for cross-site iframe (Salesforce Canvas)
    secure: true      // required with sameSite=none; works via ngrok/Heroku (trust proxy above)
  }
}));
var csrfProtection = csrf();
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
  console.log('User-Agent: ' + ua);
  console.log('isMobile: ' + res.locals.isMobile);
  next();
});

app.use('/', indexRouter);
app.use('/', authRouter);

app.get("/callback_sfdc", function (req, res) {
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
		req.session.envelope = envelope;
		console.log("req.session.envelope:", req.session.envelope);

		db.get(`SELECT value FROM store WHERE key = ?`, [req.session.envelope.context.user.email], (err, row) => {
			console.log('app - db get error: ' + err);
			const email = row ? row.value : null;
			console.log('app - db get email: ' + email);
			if (!email) {
				// email is not in the database, so we need to go through the authentication flow to get it and store it
				res.render('login');
			} else {
				// email is already in the database, so we can skip authentication and go straight to the app
				res.render('auth-success');
			}
		});		

	} else {
		res.send("authentication failed");
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

app.use(function(req, res, next) {
  res.locals.csrfToken = req.csrfToken();
  next();
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
