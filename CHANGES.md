# What changed (security & checkout pass)

## Rotate these first
The uploaded zip contained real `.env` files, so treat every value in them as exposed:
MongoDB password, Cloudinary API secret, email app password, JWT secret, Razorpay key secret.
An old Cloudinary key/secret was also sitting in a comment in `admin/src/components/cloudinary/cloudinary.js`
(removed now, but still rotate it). Changing the JWT secret signs everyone out, which is what you want.
Firebase web keys are public by design; restrict them to your domains in the Firebase console.

## Setup
1. `cp server/.env.example server/.env`, same for `client/` and `admin/`, then fill in the new values.
2. `cd server && npm install && npm run dev`
3. `cd client && npm install && npm start` (port 3008) and `cd admin && npm install && npm start` (port 3002)
4. Make yourself admin: sign up on the storefront, then `cd server && npm run make-admin -- you@example.com`
   (`--revoke` removes it). Admin accounts can no longer be created from the website.
5. `cd server && npm test` runs the security and payment tests (no database needed).

## Security fixes (server)
- Every write to products, categories, banners, attributes and uploads now requires an admin token. Reads stay public.
- Cart, wishlist and orders are private: customers only ever see their own; admins see all.
- Signup no longer accepts `isAdmin` (anyone could make themselves admin). Admin status is checked against the database on every request.
- Google sign-in now verifies a Firebase ID token (before, any email was trusted). Needs `FIREBASE_PROJECT_ID`.
- Password reset needs a short-lived token earned by entering the emailed OTP (before, anyone could reset any password).
- OTPs are generated with a secure random source, emailed only, and never returned to the browser. The endpoint that let the browser choose the OTP is retired.
- Password hash and OTP are stripped from every user response. Login tokens expire (7 days). Passwords need 8+ characters.
- `helmet`, rate limiting on login/OTP routes, CORS limited to your two apps, MongoDB operator injection stripped from queries, a central error handler.
- Fixed: editing a profile without typing a password wiped the saved password (`passwordHash` typo).

## Checkout
- The server prices the cart from the database, opens the Razorpay order, verifies the payment signature, then creates the order, takes stock atomically and clears the cart.
- The Razorpay key secret is no longer in the frontend. It lives only in `server/.env`.
- Admins can change an order's status only; amounts and payment details are locked.

## Other
- `npm start` works on macOS/Linux (was Windows-only `set PORT=`).
- `client` installs again: removed unused `react-swipeable-views` (React 17 only) and an undeclared `@mui/base` import.
- Both `api.js` files now read the login token on every request (before: stale until a full reload).
- Removed unused `stripe`, `body-parser`, `express-jwt`; `nodemon` is now a dev dependency.

## Not done yet / known
- Not run against a real MongoDB, Razorpay or Firebase project; payment and auth logic is covered by stubbed tests only.
- The Amazon-style storefront redesign and admin upgrades have not been started.
- `server/routes/user.js` keeps one module-level image array shared between requests (profile photo race); needs a refactor.
- Existing users who signed up through the admin panel are normal users until you run `make-admin`.
