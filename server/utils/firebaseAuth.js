const { createRemoteJWKSet, jwtVerify } = require('jose');

// Google publishes the public keys that sign Firebase ID tokens here.
const JWKS = createRemoteJWKSet(
    new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com')
);

// Verifies a Firebase ID token (from user.getIdToken() on the client) and returns its claims.
// Throws if the signature, issuer, audience or expiry is wrong.
async function verifyFirebaseIdToken(idToken) {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    if (!projectId) throw new Error('FIREBASE_PROJECT_ID is not configured');
    const { payload } = await jwtVerify(idToken, JWKS, {
        issuer: `https://securetoken.google.com/${projectId}`,
        audience: projectId,
        algorithms: ['RS256'],
    });
    return payload;
}

module.exports = { verifyFirebaseIdToken };
