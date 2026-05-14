# Auth0 MFA Setup Instructions

This document guides you through the Auth0 tenant configuration required for the MFA + PKCE mobile flow.

## Prerequisites

- Access to your Auth0 Dashboard with admin permissions
- The existing Regular Web Application client ID (desktop flow)
- Your app's public URL (e.g., `https://your-app.herokuapp.com`)

---

## Step 1: Enable MFA with TOTP

1. Go to **Dashboard → Security → Multi-factor Auth**
2. In the **Factors** section, toggle **One-time Password** to **ON**
3. (Optional) Disable other factors (SMS, Push, etc.) if you only want TOTP
4. In the **Define policies** section, select **Always**
   - This forces MFA on every login for all applications in the tenant
5. Click **Save**

---

## Step 2: Create Native Application for Mobile

1. Go to **Dashboard → Applications → Applications**
2. Click **Create Application**
3. Name: `Canvas Mobile` (or your preferred name)
4. Application Type: **Native**
5. Click **Create**

### Configure the Native App

6. Go to the **Settings** tab
7. Copy the **Client ID** — you'll need this for `AUTH0_MOBILE_CLIENT_ID`
8. Scroll to **Application URIs**:
   - **Allowed Callback URLs**: Add `https://your-app.herokuapp.com/callback`
   - **Allowed Logout URLs**: Add `https://your-app.herokuapp.com`
   - (Replace `your-app.herokuapp.com` with your actual app URL)
9. Scroll to **Refresh Token Rotation**:
   - Toggle **Rotation** to **ON**
   - Set **Reuse Interval** to `0` seconds
   - Set **Absolute Lifetime** to `2592000` seconds (30 days)
   - Toggle **Absolute Expiration** to **ON**
10. Scroll to **Advanced Settings → Grant Types**:
    - Ensure **Authorization Code** is checked
    - Ensure **Refresh Token** is checked
    - **Uncheck** Resource Owner Password (if present)
11. Click **Save Changes**

---

## Step 3: Update Environment Variables

Add the following to your `.env` file (and Heroku Config Vars for staging/production):

```bash
# Auth0 Mobile Client (Native app for PKCE flow)
AUTH0_MOBILE_CLIENT_ID=your_native_app_client_id_from_step_2
```

Keep existing variables:
```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_regular_web_app_client_id
AUTH0_CLIENT_SECRET=your_regular_web_app_secret
```

---

## Step 4: Verify Existing Regular Web Application

1. Go to **Dashboard → Applications → Applications** → select your existing web app
2. Go to **Settings** tab
3. Confirm **Application Type** is **Regular Web Application**
4. Scroll to **Advanced Settings → Grant Types**:
   - Ensure **Authorization Code** is checked
   - **Uncheck** Resource Owner Password (deprecated, no longer needed)
5. Click **Save Changes**

---

## Step 5: (Optional) Configure Universal Login Branding

To customize the Auth0 hosted login page that mobile users will see:

1. Go to **Dashboard → Branding → Universal Login**
2. Upload your logo
3. Set primary color to match your brand (e.g., `#635dff`)
4. Preview the login page
5. Click **Save Changes**

---

## Step 6: Test MFA Enrollment

1. Create a test user in **Dashboard → User Management → Users** (or use an existing user)
2. Open your app in a desktop browser
3. Click **Login** → enter test user credentials
4. You should see the TOTP enrollment screen:
   - **Desktop**: QR code to scan
   - **Mobile webview**: Enrollment code to copy/paste
5. Scan/enter the code in your authenticator app (Google Authenticator, Authy, etc.)
6. Enter the first 6-digit code to confirm enrollment
7. On subsequent logins, you'll be prompted for the TOTP code

---

## Troubleshooting

### "Invalid state parameter" on /callback
- The PKCE state expired (10-minute TTL). Try logging in again.
- Check that `AUTH0_MOBILE_CLIENT_ID` is set correctly.

### "MFA not prompted"
- Verify **MFA policy** is set to **Always** in Dashboard → Security → Multi-factor Auth.
- Check that the TOTP factor is toggled **ON**.

### "Refresh token not working"
- Verify **Refresh Token Rotation** is **ON** in the Native app settings.
- Check that `offline_access` scope is requested (code already includes this).
- Inspect the `refresh_tokens` SQLite table — if `created_at` is > 30 days old, the token is expired.

### "Client secret required" error for mobile
- Verify the mobile app is **Native** type, not Regular Web Application.
- Native apps do not use client secrets — PKCE provides the security.

---

## Production Cutover Checklist

Before deploying to production:

1. ✅ Separate dev tenant tested with all flows
2. ✅ PR merged to `main`
3. ✅ Reproduce Step 1 (MFA) in **production tenant**
4. ✅ Reproduce Step 2 (Native app) in **production tenant**
5. ✅ Set `AUTH0_MOBILE_CLIENT_ID` on **production Heroku app**
6. ✅ Deploy `main` to production
7. ✅ Smoke-test desktop login → MFA prompt → app renders
8. ✅ Smoke-test mobile login → MFA prompt → app renders
9. ✅ Smoke-test mobile reload → silent re-auth (no password prompt)
10. ✅ Announce to users: "MFA is now required; enroll on first login"

---

## Rollback Plan

If MFA causes issues in production:

### Option 1: Disable MFA policy (quick)
1. Dashboard → Security → Multi-factor Auth → Define policies → **Never**
2. Users can log in without MFA immediately
3. Leaves the code in place for re-enabling later

### Option 2: Revert the code (thorough)
1. `git revert <commit-hash>` on `main`
2. Deploy the revert to production
3. Set `AUTH0_MOBILE_CLIENT_ID` to empty string (or remove it)
4. Mobile flow returns to Resource Owner Password (if you kept the old code)

### Option 3: Per-app gating with Actions (advanced)
- See Appendix A in the plan file for Auth0 Actions-based per-client_id MFA gating
- Allows gradual rollout (mobile first, then web) or selective disabling
