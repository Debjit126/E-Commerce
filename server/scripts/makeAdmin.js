// Usage: npm run make-admin -- someone@example.com        (grant admin)
//        npm run make-admin -- someone@example.com --revoke (remove admin)
// The account must already exist (sign up on the storefront first). This is the only way to
// become an admin: the public signup and Google sign-in endpoints always create normal users.
require('dotenv/config');
const mongoose = require('mongoose');
const { User } = require('../models/user');

(async () => {
    const [email, flag] = process.argv.slice(2);
    if (!email) {
        console.error('Usage: npm run make-admin -- <email> [--revoke]');
        process.exit(1);
    }
    await mongoose.connect(process.env.CONNECTION_STRING);
    const user = await User.findOne({ email });
    if (!user) {
        console.error(`No user found with email ${email}. Sign up first, then run this again.`);
        await mongoose.disconnect();
        process.exit(1);
    }
    user.isAdmin = flag !== '--revoke';
    await user.save();
    console.log(`${email} is ${user.isAdmin ? 'now an admin' : 'no longer an admin'}.`);
    await mongoose.disconnect();
})().catch((err) => { console.error(err); process.exit(1); });
