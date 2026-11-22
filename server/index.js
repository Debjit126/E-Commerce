require('dotenv/config');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');

const { User } = require('./models/user');
const { Cart } = require('./models/cart');
const { MyList } = require('./models/myList');
const { Orders } = require('./models/orders');
const { requireAuth, requireAdmin, adminWrites, ownedBy } = require('./middleware/auth');

const REQUIRED_ENV = ['CONNECTION_STRING', 'JSON_WEB_TOKEN_SECRET_KEY', 'PORT'];
const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missing.length) {
    console.error(`Missing required environment variables: ${missing.join(', ')}`);
    process.exit(1);
}

const app = express();
app.set('trust proxy', 1);

// Only the storefront and the admin panel may call the API from a browser.
const allowedOrigins = (process.env.CORS_ORIGINS || process.env.CLIENT_BASE_URL || '')
    .split(',').map((o) => o.trim()).filter(Boolean);
app.use(cors({
    origin: (origin, cb) => {
        // In development any localhost port is fine (React picks another port if 3008/3002 is busy).
        const isLocalDev = process.env.NODE_ENV !== 'production' && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin || '');
        if (!origin || isLocalDev || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true);
        return cb(new Error('Origin not allowed by CORS'));
    },
}));

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '1mb' }));
app.use(mongoSanitize()); // strips $ and . operators so query strings cannot inject MongoDB operators

// Brute-force protection on anything that signs in, verifies a code or sends an email.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: true, success: false, msg: 'Too many attempts. Please try again later.' },
});
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false });
app.use('/api', apiLimiter);
['signin', 'signup', 'verifyemail', 'forgotPassword', 'verifyAccount', 'authWithGoogle']
    .forEach((p) => app.use(`/api/user/${p}`, authLimiter));

app.get('/health', (req, res) => res.json({ status: 'ok' }));

//Routes
const userRoutes = require('./routes/user.js');
const categoryRoutes = require('./routes/categories');
const productRoutes = require('./routes/products');
const imageUploadRoutes = require('./helper/imageUpload.js');
const productWeightRoutes = require('./routes/productWeight.js');
const productRAMSRoutes = require('./routes/productRAMS.js');
const productSIZESRoutes = require('./routes/productSize.js');
const productReviews = require('./routes/productReviews.js');
const cartRoutes = require('./routes/cart.js');
const myListRoutes = require('./routes/myList.js');
const ordersRoutes = require('./routes/orders.js');
const homeBannerRoutes = require('./routes/homeBanner.js');
const searchRoutes = require('./routes/search.js');
const bannersRoutes = require('./routes/banners.js');
const homeSideBannerRoutes = require('./routes/homeSideBanner.js');
const homeBottomBannerRoutes = require('./routes/homeBottomBanner.js');

// Image uploads: fail fast with a clear message if Cloudinary is not configured.
const requireCloudinary = require('./middleware/cloudinaryGuard');
['/api/products', '/api/category', '/api/banners', '/api/homeBanner', '/api/homeSideBanners', '/api/homeBottomBanners', '/api/user']
    .forEach((base) => app.post(`${base}/upload`, base === '/api/user' ? requireAuth : requireAdmin, requireCloudinary));

// Account routes guard themselves (some are public: signin, signup, OTP).
app.use('/api/user', userRoutes);
app.use('/uploads', express.static('uploads'));

// Catalog: anyone can read, only admins can change.
app.use('/api/category', adminWrites(), categoryRoutes);
app.use('/api/products', adminWrites({ authOnly: ['/recentlyViewd'] }), productRoutes);
app.use('/api/imageUpload', requireAdmin, imageUploadRoutes);
app.use('/api/productWeight', adminWrites(), productWeightRoutes);
app.use('/api/productRAMS', adminWrites(), productRAMSRoutes);
app.use('/api/productSIZE', adminWrites(), productSIZESRoutes);
app.use('/api/homeBanner', adminWrites(), homeBannerRoutes);
app.use('/api/banners', adminWrites(), bannersRoutes);
app.use('/api/homeSideBanners', adminWrites(), homeSideBannerRoutes);
app.use('/api/homeBottomBanners', adminWrites(), homeBottomBannerRoutes);
app.use('/api/search', searchRoutes);

// Reviews: public to read, signed-in users to write.
app.use('/api/productReviews', (req, res, next) => (req.method === 'GET' ? next() : requireAuth(req, res, next)), productReviews);

// Per-user data: each user sees only their own cart, wishlist and orders; admins see all.
app.use('/api/cart', ownedBy(Cart, 'userId'), cartRoutes);
app.use('/api/my-list', ownedBy(MyList, 'userId'), myListRoutes);
app.use('/api/orders', ordersRoutes); // guards are applied per route (payment flow + admin dashboards)

// Central error handler: never leak stack traces to clients.
app.use((err, req, res, next) => {
    if (err && err.message === 'Origin not allowed by CORS') {
        return res.status(403).json({ success: false, msg: err.message });
    }
    if (err && err.name === 'UnauthorizedError') {
        return res.status(401).json({ success: false, msg: 'Invalid or expired token' });
    }
    console.error(err);
    res.status(err.status || 500).json({ success: false, msg: 'Something went wrong' });
});

//Database
if (require.main === module) {
    mongoose.connect(process.env.CONNECTION_STRING)
        .then(() => {
            console.log('Database Connection is ready...');
            app.listen(process.env.PORT, () => {
                console.log(`server is running http://localhost:${process.env.PORT}`);
            });
        })
        .catch((err) => {
            console.error(err);
            process.exit(1);
        });
}

module.exports = app;
