// Run with: npm test
// These tests stub the database models and Razorpay, so they need no MongoDB or network.
process.env.CONNECTION_STRING = 'mongodb://stub';
process.env.JSON_WEB_TOKEN_SECRET_KEY = 'test-secret';
process.env.PORT = '0';
process.env.FIREBASE_PROJECT_ID = 'demo-project';
process.env.RAZORPAY_KEY_ID = 'rzp_test_key';
process.env.RAZORPAY_KEY_SECRET = 'rzp_test_secret';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');

// Never send real emails from tests.
require.cache[require.resolve('../utils/emailService')] = {
    id: 'email', filename: 'email', loaded: true,
    exports: { sendEmail: async () => ({ success: true }) },
};

// Fake Razorpay SDK.
const razorpayOrders = new Map();
class FakeRazorpay {
    constructor() {
        this.orders = {
            create: async (o) => { const id = `order_${razorpayOrders.size + 1}`; const rec = { id, ...o }; razorpayOrders.set(id, rec); return rec; },
            fetch: async (id) => razorpayOrders.get(id),
        };
    }
}
require.cache[require.resolve('razorpay')] = { id: 'rzp', filename: 'rzp', loaded: true, exports: FakeRazorpay };

const { User } = require('../models/user');
const { Cart } = require('../models/cart');
const { Orders } = require('../models/orders');
const { Product } = require('../models/products');
const app = require('../index');

const ALICE = 'a'.repeat(24);
const BOB = 'b'.repeat(24);
const ROOT = 'c'.repeat(24);
const PRODUCT = 'd'.repeat(24);
const tokenFor = (id) => jwt.sign({ id, email: `${id.slice(0, 3)}@example.com` }, process.env.JSON_WEB_TOKEN_SECRET_KEY, { expiresIn: '1h' });
const users = { [ALICE]: { isAdmin: false }, [BOB]: { isAdmin: false }, [ROOT]: { isAdmin: true } };
User.findById = (id) => ({ select: async () => users[id] || null });

test('anonymous users cannot write to the catalog', async () => {
    for (const [method, url] of [['post', '/api/products/create'], ['delete', `/api/products/${PRODUCT}`], ['post', '/api/category/create'], ['put', `/api/orders/${PRODUCT}`]]) {
        const res = await request(app)[method](url).send({});
        assert.equal(res.status, 401, `${method} ${url}`);
    }
});

test('a normal customer is rejected from admin endpoints', async () => {
    const t = tokenFor(ALICE);
    for (const [method, url] of [['post', '/api/products/create'], ['post', '/api/banners/create'], ['get', '/api/user'], ['get', '/api/orders/sales?year=2026'], ['delete', `/api/user/${BOB}`]]) {
        const res = await request(app)[method](url).set('Authorization', `Bearer ${t}`).send({});
        assert.equal(res.status, 403, `${method} ${url}`);
    }
});

test('expired and forged tokens are rejected', async () => {
    const forged = jwt.sign({ id: ROOT }, 'wrong-secret');
    assert.equal((await request(app).get('/api/user').set('Authorization', `Bearer ${forged}`)).status, 401);
    const expired = jwt.sign({ id: ROOT }, process.env.JSON_WEB_TOKEN_SECRET_KEY, { expiresIn: -10 });
    assert.equal((await request(app).get('/api/user').set('Authorization', `Bearer ${expired}`)).status, 401);
});

test('signup can never create an admin', async () => {
    let saved;
    User.findOne = async () => null;
    const original = User.prototype.save;
    User.prototype.save = async function () { saved = this; return this; };
    const res = await request(app).post('/api/user/signup').send({ name: 'Eve', email: 'eve@example.com', phone: '1', password: 'longenough1', isAdmin: true });
    User.prototype.save = original;
    assert.equal(res.status, 200);
    assert.equal(saved.isAdmin, false);
    assert.equal(res.body.token, undefined, 'no token before email verification');
});

test('signup enforces a minimum password length', async () => {
    const res = await request(app).post('/api/user/signup').send({ name: 'Eve', email: 'eve@example.com', password: 'short' });
    assert.equal(res.status, 400);
});

test('Google sign-in rejects forged requests that carry no verified token', async () => {
    let res = await request(app).post('/api/user/authWithGoogle').send({ email: 'root@example.com', isAdmin: true });
    assert.equal(res.status, 400);
    res = await request(app).post('/api/user/authWithGoogle').send({ idToken: 'not-a-real-token', email: 'root@example.com' });
    assert.equal(res.status, 401);
});

test('password reset requires proof of email ownership', async () => {
    let res = await request(app).post('/api/user/forgotPassword/changePassword').send({ email: 'victim@example.com', newPass: 'newpassword1' });
    assert.equal(res.status, 403);
    const wrongPurpose = jwt.sign({ email: 'victim@example.com', purpose: 'login' }, process.env.JSON_WEB_TOKEN_SECRET_KEY);
    res = await request(app).post('/api/user/forgotPassword/changePassword').send({ email: 'victim@example.com', newPass: 'newpassword1', resetToken: wrongPurpose });
    assert.equal(res.status, 403);
});

test('OTP is never returned to the browser', async () => {
    const doc = { save: async () => {} };
    User.findOne = async () => doc;
    const res = await request(app).post('/api/user/verifyAccount/resendOtp').send({ email: 'x@example.com' });
    assert.equal(res.status, 200);
    assert.equal(res.body.otp, null);
    assert.match(doc.otp, /^\d{6}$/);
});

test('user JSON never contains the password hash or OTP', () => {
    const json = new User({ name: 'A', email: 'a@example.com', password: 'hash', otp: '123456' }).toJSON();
    assert.equal(json.password, undefined);
    assert.equal(json.otp, undefined);
});

test('customers can only list their own cart and orders', async () => {
    let cartFilter, orderFilter;
    Cart.find = async (f) => { cartFilter = f; return []; };
    Orders.find = (f) => { orderFilter = f; return { sort: async () => [] }; };
    await request(app).get(`/api/cart?userId=${BOB}`).set('Authorization', `Bearer ${tokenFor(ALICE)}`);
    assert.deepEqual(cartFilter, { userId: ALICE });
    await request(app).get(`/api/orders?userid=${BOB}`).set('Authorization', `Bearer ${tokenFor(ALICE)}`);
    assert.deepEqual(orderFilter, { userid: ALICE });
    await request(app).get(`/api/orders?userid=${BOB}`).set('Authorization', `Bearer ${tokenFor(ROOT)}`);
    assert.equal(orderFilter.userid, BOB, 'admins may filter freely');
});

test('operator injection in query strings is stripped', async () => {
    let filter;
    Orders.find = (f) => { filter = f; return { sort: async () => [] }; };
    await request(app).get('/api/orders?userid[$ne]=x').set('Authorization', `Bearer ${tokenFor(ROOT)}`);
    assert.equal(JSON.stringify(filter).includes('$ne'), false);
});

test('a customer cannot touch another customer\'s cart item', async () => {
    const item = 'e'.repeat(24);
    Cart.findById = () => ({ select: async () => ({ userId: BOB }) });
    const res = await request(app).delete(`/api/cart/${item}`).set('Authorization', `Bearer ${tokenFor(ALICE)}`);
    assert.equal(res.status, 403);
});

// ---- payments ----------------------------------------------------------------

function stubShop({ cartPrice = 1, qty = 2, stock = 5, dbPrice = 500 } = {}) {
    Cart.find = async () => [{ productId: PRODUCT, productTitle: 'Shirt', quantity: qty, price: cartPrice, image: 'x.png' }];
    Product.find = async () => [{ _id: PRODUCT, name: 'Shirt', price: dbPrice, countInStock: stock, images: ['img.png'] }];
    const stockLog = [];
    Product.updateOne = async (q, u) => { stockLog.push(u.$inc.countInStock); return { modifiedCount: q.countInStock && q.countInStock.$gte > stock ? 0 : 1 }; };
    Orders.findOne = async () => null;
    Orders.create = async (doc) => ({ ...doc, id: 'o1' });
    Cart.deleteMany = async () => ({});
    return stockLog;
}
const sign = (orderId, paymentId, secret = process.env.RAZORPAY_KEY_SECRET) => crypto.createHmac('sha256', secret).update(`${orderId}|${paymentId}`).digest('hex');
const ship = { name: 'Ann', phoneNumber: '999', address: '1 Road', pincode: '700001' };

test('payment amount comes from database prices, not the browser cart', async () => {
    stubShop({ cartPrice: 1, qty: 2, dbPrice: 500 });
    const res = await request(app).post('/api/orders/razorpay/create').set('Authorization', `Bearer ${tokenFor(ALICE)}`).send({ amount: 1 });
    assert.equal(res.status, 200);
    assert.equal(res.body.amount, 100000); // 2 x 500 INR in paise
    assert.equal(res.body.keyId, 'rzp_test_key');
    assert.equal(JSON.stringify(res.body).includes('rzp_test_secret'), false);
});

test('checkout refuses out-of-stock items', async () => {
    stubShop({ qty: 9, stock: 3 });
    const res = await request(app).post('/api/orders/razorpay/create').set('Authorization', `Bearer ${tokenFor(ALICE)}`).send({});
    assert.equal(res.status, 409);
});

test('an order is created only for a genuine, matching payment', async () => {
    stubShop();
    const t = tokenFor(ALICE);
    const create = await request(app).post('/api/orders/razorpay/create').set('Authorization', `Bearer ${t}`).send({});
    const orderId = create.body.razorpayOrderId;

    let res = await request(app).post('/api/orders/razorpay/verify').set('Authorization', `Bearer ${t}`)
        .send({ ...ship, razorpay_order_id: orderId, razorpay_payment_id: 'pay_1', razorpay_signature: sign(orderId, 'pay_1', 'attacker-secret') });
    assert.equal(res.status, 400, 'forged signature');

    res = await request(app).post('/api/orders/razorpay/verify').set('Authorization', `Bearer ${tokenFor(BOB)}`)
        .send({ ...ship, razorpay_order_id: orderId, razorpay_payment_id: 'pay_1', razorpay_signature: sign(orderId, 'pay_1') });
    assert.equal(res.status, 403, "someone else's payment");

    res = await request(app).post('/api/orders/razorpay/verify').set('Authorization', `Bearer ${t}`)
        .send({ ...ship, razorpay_order_id: orderId, razorpay_payment_id: 'pay_1', razorpay_signature: sign(orderId, 'pay_1') });
    assert.equal(res.status, 201);
    assert.equal(res.body.amount, '1000');
    assert.equal(res.body.status, 'pending');
    assert.equal(res.body.userid, ALICE);
});

test('verify rejects an order whose cart total no longer matches the payment', async () => {
    stubShop({ dbPrice: 500 });
    const t = tokenFor(ALICE);
    const { body } = await request(app).post('/api/orders/razorpay/create').set('Authorization', `Bearer ${t}`).send({});
    stubShop({ dbPrice: 900 }); // price changed after payment started
    const res = await request(app).post('/api/orders/razorpay/verify').set('Authorization', `Bearer ${t}`)
        .send({ ...ship, razorpay_order_id: body.razorpayOrderId, razorpay_payment_id: 'pay_2', razorpay_signature: sign(body.razorpayOrderId, 'pay_2') });
    assert.equal(res.status, 409);
});

test('only the status of an order can be changed, and only to a known value', async () => {
    Orders.findByIdAndUpdate = async (id, upd) => ({ id, ...upd });
    const t = tokenFor(ROOT);
    let res = await request(app).put(`/api/orders/${PRODUCT}`).set('Authorization', `Bearer ${t}`).send({ status: 'confirm', amount: '1' });
    assert.equal(res.status, 200);
    assert.deepEqual(Object.keys(res.body).sort(), ['id', 'status']);
    res = await request(app).put(`/api/orders/${PRODUCT}`).set('Authorization', `Bearer ${t}`).send({ status: 'hacked' });
    assert.equal(res.status, 400);
});

test('image upload fails fast with a clear message when Cloudinary is not configured', async () => {
    delete process.env.cloudinary_Config_Cloud_Name;
    const res = await request(app).post('/api/products/upload').set('Authorization', `Bearer ${tokenFor(ROOT)}`);
    assert.equal(res.status, 503);
    assert.match(res.body.msg, /cloudinary_Config_Cloud_Name/);
});

test('image upload still requires an admin', async () => {
    const res = await request(app).post('/api/products/upload');
    assert.equal(res.status, 401);
});
