import { initializeApp } from "firebase/app";

const firebaseConfig = {
  apiKey: process.env.REACT_APP_FIREBASE_API_KEY,
  authDomain: process.env.REACT_APP_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.REACT_APP_FIREBASE_PROJECT_ID,
  storageBucket: process.env.REACT_APP_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.REACT_APP_FIREBASE_APP_ID,
};

const missing = Object.entries({
  REACT_APP_FIREBASE_API_KEY: firebaseConfig.apiKey,
  REACT_APP_FIREBASE_AUTH_DOMAIN: firebaseConfig.authDomain,
  REACT_APP_FIREBASE_PROJECT_ID: firebaseConfig.projectId,
  REACT_APP_FIREBASE_APP_ID: firebaseConfig.appId,
})
  .filter(([, value]) => !value)
  .map(([name]) => name);

export const isFirebaseConfigured = missing.length === 0;

if (!isFirebaseConfigured) {
  // Without this the whole app crashes with "auth/invalid-api-key" before any page loads.
  console.error(
    `Firebase is not configured. Missing in .env: ${missing.join(", ")}. ` +
      "Create the .env file in this app's root folder (next to package.json) and restart `npm start`. " +
      "Email/password login still works; Google sign-in will not."
  );
  firebaseConfig.apiKey = firebaseConfig.apiKey || "missing-api-key";
}

export const firebaseApp = initializeApp(firebaseConfig);
