const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { User } = require('../models/user');

const SECRET = () => process.env.JSON_WEB_TOKEN_SECRET_KEY;

function signToken(user) {
    return jwt.sign(
        { email: user.email, id: String(user._id) },
        SECRET(),
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
}

// Verifies the Bearer token and sets req.auth = { id, email }.
function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
        return res.status(401).json({ success: false, msg: 'Authentication required' });
    }
    try {
        const payload = jwt.verify(token, SECRET(), { algorithms: ['HS256'] });
        req.auth = { id: String(payload.id), email: payload.email };
        return next();
    } catch (err) {
        return res.status(401).json({ success: false, msg: 'Invalid or expired token' });
    }
}

// Admin status is read from the database on every request, so demoting an admin
// takes effect immediately instead of waiting for the token to expire.
function requireAdmin(req, res, next) {
    requireAuth(req, res, async () => {
        try {
            const user = await User.findById(req.auth.id).select('isAdmin');
            if (!user || !user.isAdmin) {
                return res.status(403).json({ success: false, msg: 'Admin access required' });
            }
            req.auth.isAdmin = true;
            return next();
        } catch (err) {
            return res.status(500).json({ success: false, msg: 'Authorization check failed' });
        }
    });
}

// Marks req.auth.isAdmin without rejecting non-admins.
async function resolveAdmin(req) {
    if (req.auth.isAdmin !== undefined) return req.auth.isAdmin;
    const user = await User.findById(req.auth.id).select('isAdmin');
    req.auth.isAdmin = !!(user && user.isAdmin);
    return req.auth.isAdmin;
}

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

// Public reads, admin-only writes. `authOnly` lists write paths any signed-in user may call.
function adminWrites({ authOnly = [] } = {}) {
    return (req, res, next) => {
        if (SAFE.has(req.method)) return next();
        if (authOnly.includes(req.path)) return requireAuth(req, res, next);
        return requireAdmin(req, res, next);
    };
}

// For collections owned by a user (cart, wishlist, orders): a signed-in user may only
// see or change their own documents; admins may access everything.
function ownedBy(Model, field) {
    const idPath = /^\/([a-fA-F0-9]{24})$/;
    return [requireAuth, async (req, res, next) => {
        try {
            if (await resolveAdmin(req)) return next();

            if (req.method === 'GET' && req.path === '/') {
                // Replace any client-supplied filter: users only ever list their own documents.
                req.query = { [field]: req.auth.id };
                return next();
            }
            if (req.method === 'POST' && req.body) {
                req.body[field] = req.auth.id;
                return next();
            }
            const m = idPath.exec(req.path);
            if (m) {
                const doc = await Model.findById(m[1]).select(field);
                if (!doc) return res.status(404).json({ success: false, msg: 'Not found' });
                if (String(doc[field]) !== req.auth.id) {
                    return res.status(403).json({ success: false, msg: 'Forbidden' });
                }
            }
            return next();
        } catch (err) {
            return res.status(500).json({ success: false, msg: 'Authorization check failed' });
        }
    }];
}

// Users may touch their own account; admins may touch any.
async function selfOrAdmin(req, res, next) {
    try {
        if (req.auth.id === req.params.id || (await resolveAdmin(req))) return next();
        return res.status(403).json({ success: false, msg: 'Forbidden' });
    } catch (err) {
        return res.status(500).json({ success: false, msg: 'Authorization check failed' });
    }
}

function isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

module.exports = { signToken, requireAuth, requireAdmin, adminWrites, ownedBy, selfOrAdmin, resolveAdmin, isValidObjectId };
