const crypto = require('crypto');

// Cryptographically secure 6-digit code (Math.random is predictable).
const generateOtp = () => String(crypto.randomInt(100000, 1000000));

module.exports = { generateOtp };
