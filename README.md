# Salesforce Canvas Demo with OAuth

Node.js app showcasing Salesforce Canvas integration with Auth0 OAuth authentication, supporting both desktop (browser popup) and mobile (Salesforce Mobile SDK / WKWebView) flows.

---

## Overview

This app is embedded inside Salesforce as a Canvas app. Salesforce sends a signed `signed_request` payload to the app via HTTP POST. The app validates the [HMAC](https://en.wikipedia.org/wiki/HMAC) (sometimes expanded as either keyed-hash message authentication code or hash-based message authentication code) signature, decodes the Canvas envelope (which contains the user's identity and Salesforce context), and authenticates the user against Auth0 before rendering the app UI.

The app supports two authentication paths:

- **Desktop**: Auth0 Universal Login opened in a popup window using the OpenID Connect flow
- **Mobile (Salesforce Mobile)**: Email/password form submitting directly to Auth0's Resource Owner Password grant, because the WKWebView in Salesforce's mobile container cannot reliably open browser popups

---

## Architecture

```
Salesforce Canvas
      │
      │  POST / (signed_request)
      ▼
  Express App (app.js)
      │
      ├── HMAC verify signed_request
      ├── Decode Canvas envelope
      │
      ├── [User known in DB] ──► render index.ejs directly
      │
      └── [User unknown] ──► render login.ejs
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
               Desktop                       Mobile
            GET /login                  POST /login-mobile
         (Auth0 popup)              (Resource Owner Password)
                    │                           │
            GET /callback               render index.ejs directly
         POST /auth-success
```

**Key design constraint**: The Salesforce Canvas `POST /` is issued by Salesforce's infrastructure, not by the user's WKWebView. The `Set-Cookie` response header therefore never reaches the mobile browser's cookie jar. The entire mobile flow is **stateless with respect to session cookies** — all necessary context travels through hidden form fields (`signed_request`) and is re-validated on every request.

---

## Project Structure

```
├── app.js                  # Express app entry point, Canvas signed_request handler
├── db.js                   # SQLite setup (user email → Auth0 user ID store)
├── lib/
│   ├── canvas.js           # decodeSignedRequest() — HMAC verification + envelope decode
│   └── salesforce.js       # getAccountName() — Salesforce Account API helper
├── routes/
│   ├── auth.js             # Auth routes: /login, /login-mobile, /callback, /auth-success, /logout
│   └── index.js            # App routes: GET /, POST /updateAccount
├── views/
│   ├── login.ejs           # Login page (desktop: Auth0 button; mobile: email/password form)
│   ├── index.ejs           # Main app page (account name editor)
│   ├── auth-success.ejs    # Desktop post-login bridge (closes popup, reloads parent)
│   ├── callback.ejs        # Salesforce OAuth callback page
│   └── error.ejs           # Error page
├── var/db/
│   ├── sessions.db         # express-session SQLite store
│   └── store.db            # User email → Auth0 user ID mapping
├── certs/                  # Local HTTPS certificates (development only)
├── .env.example            # Template for all required environment variables
└── test/
    └── test.http           # Manual HTTP test requests
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `express` | HTTP server and routing |
| `passport` + `passport-openidconnect` | Desktop OAuth via Auth0 OpenID Connect |
| `express-session` + `connect-sqlite3` | Session store (desktop flow) |
| `csurf` | CSRF protection (cookie mode) |
| `axios` | Auth0 token exchange and Salesforce API calls |
| `ejs` | Server-side HTML templating |
| `sqlite3` + `mkdirp` | User identity persistence |
| `body-parser` | Request body parsing |
| `cookie-parser` | Cookie parsing (required for CSRF cookie mode) |
| `morgan` | HTTP request logging |
| `dotenv` | Environment variable loading |

---

## Environment Configuration

### Prerequisites

1. A Salesforce org with a Connected App configured as a Canvas app
2. An Auth0 tenant with:
   - A Regular Web Application (for the desktop OpenID Connect flow)
   - The Resource Owner Password grant enabled (for the mobile flow)
   - A Username-Password-Authentication database connection

### Local Development

```bash
npm install

# Generate local HTTPS certs (required — Canvas requires HTTPS)
# Place localhost.pem and localhost-key.pem in ./certs/

# Copy the example env file and fill in your values
cp .env.example .env

npm start
```

### Heroku Deployment

Set all environment variables in Heroku Config Vars (Settings → Config Vars) and deploy via the button above or `git push heroku main`.


### Salesforce Configuration

#### Part 1: Create a visualforce **CanvasJS** using the following apex code:
```
<apex:page >
    <apex:canvasApp applicationName="CanvasJS" height="500px" width="500px"/>
</apex:page>
```

Enable the option "Available for Lightning Experience, Experience Builder sites, and the mobile app"


#### Part 2: Create the External Client App: 
---
**Section Policies > App Policies**
- Start Page: `OAuth`
- Selected Profiles: `System Administrator` (only for testing)


**Section Policies > OAuth Policies**
- Permited Users: `Admin approved users are pre-authorized`
- OAuth Start URL: `the-url-where-is-running-the-nodejs-project/callback_sfdc`
---

**Section Settings**

**Fields:**
- External Client App Name: `CanvasJS`
- API Name: `CanvasJS`
- Contact Email: `your email`

**OAuth Settings:**
- Canvas App URL: `the-url-where-is-running-the-nodejs-project/callback_sfdc`

**Selected OAuth Scopes:**
- `Access the identity URL service (id, profile, email, address, phone)`
- `Manage user data via APIs (api)`
- `Full access (full)`
- `Perform requests at any time (refresh_token, offline_access)`
- `Access the Salesforce API Platform (sfap_api)`

**Canvas App Settings:**

- Canvas App URL: `the-url-where-is-running-the-nodejs-project`
- Access Method: `Signed Request (POST)`
- Locations: `Visualforce Page` and `Lightning Component`
---
#### Part 3: Add the visualforce component to the Account page 

- Open the Account record page 
- In the ***Setup Menu*** click on **Edit Page**
- Position the visualforce component on the page

---

## Environment Variables

Copy `.env.example` to `.env` and fill in the values. All variables are required unless a default is noted.

| Variable | Description |
|---|---|
| `CANVAS_CONSUMER_SECRET` | Consumer secret from the Salesforce Connected App — used to verify the `signed_request` HMAC |
| `SALESFORCE_DOMAIN` | Salesforce org instance hostname, e.g. `mycompany.my.salesforce.com` — used to load the Canvas SDK |
| `AUTH0_DOMAIN` | Auth0 tenant domain, e.g. `your-tenant.auth0.com` |
| `AUTH0_CLIENT_ID` | Auth0 application Client ID |
| `AUTH0_CLIENT_SECRET` | Auth0 application Client Secret |
| `AUTH0_CONNECTION` | Auth0 database connection name (default: `Username-Password-Authentication`) |
| `SESSION_SECRET` | Strong random secret for signing session cookies — generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `URL` | Public base URL of this app, e.g. `https://your-app.herokuapp.com` — used to build the OAuth callback URL and `postMessage` origin |
| `PORT` | Port to listen on (set automatically by Heroku) |
| `LOCAL_HTTPS` | Set to `true` to enable the local HTTPS server using certs in `./certs/` |

---

## Security

### Canvas Signature Verification

Every `POST /` from Salesforce is verified by recomputing the HMAC-SHA256 of the base64-encoded envelope using `CANVAS_CONSUMER_SECRET` and comparing it to the signature prefix in `signed_request`. Requests that fail this check are rejected immediately.

The same verification is applied in `POST /login-mobile` and `POST /updateAccount` when the `signed_request` arrives via form body, ensuring the envelope cannot be tampered with by the client.

### CSRF Protection

CSRF protection uses `csurf` in **cookie mode** (`csrf({ cookie: true })`). Session-based CSRF was not viable because the mobile WKWebView does not maintain session cookies, so the CSRF secret is stored in a `_csrf` cookie instead.

### Stateless Mobile Flow

The mobile flow intentionally avoids relying on server-side sessions. The Canvas envelope is re-decoded from the `signed_request` hidden field on each request rather than read from `req.session`. This is necessary because the Salesforce Mobile WKWebView operates in a cross-origin iframe context and does not reliably propagate `Set-Cookie` headers across redirects.

### Credentials

- The session secret is read from `SESSION_SECRET` in the environment. Generate a strong value with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.
- Auth0 credentials and the Canvas consumer secret are never exposed to the client.
- Auth0 `error_description` values are logged server-side only; the client always receives a generic error message.

---

## Design Decisions

### Why not use session cookies for the mobile flow?

The initial Salesforce Canvas `POST /` is sent by **Salesforce's backend servers**, not the user's device. The `Set-Cookie` response header goes back to Salesforce's infrastructure, not the WKWebView. All subsequent requests from the WKWebView therefore carry no matching session cookie — making any server-side session state unreachable for the mobile flow.

### Why render the page directly instead of redirecting after login?

After `POST /login-mobile` succeeds, the app renders `index.ejs` in the same POST response instead of issuing a `302` redirect to `GET /`. The WKWebView does not reliably update its cookie jar when following a cross-origin redirect, so a redirect to `GET /` would again arrive with no session. Rendering directly eliminates the redirect entirely.

### Why carry `signed_request` through every form?

Since session state is unavailable, the Canvas envelope (containing the Salesforce OAuth token, instance URL, and record context) must travel with the user through the entire interaction. It is embedded as a hidden field in every HTML form (`login.ejs`, `index.ejs`) and re-validated with HMAC on the server on each submission.

### Why Auth0 Resource Owner Password grant for mobile?

The standard OpenID Connect flow requires opening a browser popup or redirect, which is unreliable inside Salesforce's Cordova/WKWebView container on mobile. The Resource Owner Password grant allows credentials to be submitted directly from a form inside the WebView without any popup or external navigation.

### Why SQLite?

The app stores a mapping of Salesforce user email → Auth0 user ID to avoid requiring Auth0 authentication on every Canvas load once a user has logged in once. SQLite is sufficient for a demo app and requires no additional infrastructure. On Heroku the database is ephemeral (resets on dyno restart); a persistent store (Postgres, Redis) would be needed for production.

---

*Credits: [Jitendra Zaa](https://www.jitendrazaa.com/) for the original Canvas + Node.js integration pattern.*
This app was created using the resources below as a reference: [Video](https://www.youtube.com/watch?v=FhMzTt8IShw&feature=youtu.be) and [Blog Post](https://www.jitendrazaa.com/blog/salesforce/salesforce-integration-with-nodejs-based-applications-using-canvas/)
