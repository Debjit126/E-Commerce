const crypto = require('crypto');
const express = require('express');
const Razorpay = require('razorpay');

const { Orders } = require('../models/orders');
const { Product } = require('../models/products');
const { Cart } = require('../models/cart');
const { requireAuth, requireAdmin, resolveAdmin, isValidObjectId } = require('../middleware/auth');

const router = express.Router();

const MONTHS = ['JAN', 'FEB', 'MAR', 'APRIL', 'MAY', 'JUNE', 'JULY', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const ORDER_STATUSES = Orders.schema.path('status').enumValues;

const httpError = (status, message) => Object.assign(new Error(message), { status });

function getRazorpay() {
    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
        throw httpError(503, 'Payments are not configured');
    }
    return new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
}

// Prices the user's cart from the database. Prices and quantities sent by the browser are never trusted.
async function priceCart(userId, { checkStock = true } = {}) {
    const items = await Cart.find({ userId });
    if (!items.length) throw httpError(400, 'Your cart is empty');

    const ids = items.map((i) => i.productId).filter(isValidObjectId);
    const products = await Product.find({ _id: { $in: ids } });
    const byId = new Map(products.map((p) => [String(p._id), p]));

    let total = 0;
    const lines = [];
    for (const item of items) {
        const product = byId.get(String(item.productId));
        if (!product) throw httpError(400, `"${item.productTitle}" is no longer available`);

        const quantity = Math.max(1, Math.floor(Number(item.quantity) || 0));
        if (checkStock && product.countInStock < quantity) {
            throw httpError(409, product.countInStock > 0
                ? `Only ${product.countInStock} of "${product.name}" left in stock`
                : `"${product.name}" is out of stock`);
        }

        const subTotal = product.price * quantity;
        total += subTotal;
        lines.push({
            productId: String(product._id),
            productTitle: product.name,
            quantity,
            price: product.price,
            image: (product.images && product.images[0]) || item.image,
            subTotal,
        });
    }
    return { lines, total };
}

const handle = (fn) => async (req, res) => {
    try {
        await fn(req, res);
    } catch (err) {
        if (err.status) return res.status(err.status).json({ success: false, message: err.message });
        console.error(err);
        res.status(500).json({ success: false, message: 'Something went wrong' });
    }
};

// ---------------------------------------------------------------------------
// Checkout (signed-in customers)
// ---------------------------------------------------------------------------

// Step 1: price the cart on the server and open a Razorpay order for exactly that amount.
router.post('/razorpay/create', requireAuth, handle(async (req, res) => {
    const { total } = await priceCart(req.auth.id);
    const order = await getRazorpay().orders.create({
        amount: Math.round(total * 100),
        currency: 'INR',
        receipt: `rcpt_${Date.now()}`,
        notes: { userId: req.auth.id },
    });
    res.json({
        razorpayOrderId: order.id,
        amount: order.amount,
        currency: order.currency,
        keyId: process.env.RAZORPAY_KEY_ID,
    });
}));

// Step 2: after the customer pays, prove the payment is genuine, then create the order.
router.post('/razorpay/verify', requireAuth, handle(async (req, res) => {
    const {
        razorpay_order_id, razorpay_payment_id, razorpay_signature,
        name, phoneNumber, address, pincode,
    } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        throw httpError(400, 'Missing payment details');
    }
    if (![name, phoneNumber, address, pincode].every((v) => typeof v === 'string' && v.trim())) {
        throw httpError(400, 'Delivery details are incomplete');
    }

    const expected = crypto
        .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || '')
        .update(`${razorpay_order_id}|${razorpay_payment_id}`)
        .digest('hex');
    const a = Buffer.from(expected);
    const b = Buffer.from(String(razorpay_signature));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        throw httpError(400, 'Payment verification failed');
    }

    // The same payment can only ever create one order (safe to retry).
    const already = await Orders.findOne({ paymentId: razorpay_payment_id });
    if (already) {
        if (already.userid !== req.auth.id) throw httpError(409, 'Payment already used');
        return res.status(200).json(already);
    }

    const rpOrder = await getRazorpay().orders.fetch(razorpay_order_id);
    if (!rpOrder || (rpOrder.notes && rpOrder.notes.userId) !== req.auth.id) {
        throw httpError(403, 'This payment does not belong to your account');
    }

    const { lines, total } = await priceCart(req.auth.id, { checkStock: false });
    if (Math.round(total * 100) !== Number(rpOrder.amount)) {
        console.error(`Cart changed after payment ${razorpay_payment_id} (user ${req.auth.id})`);
        throw httpError(409, `Your cart changed after the payment was started. Please contact support with payment ID ${razorpay_payment_id}.`);
    }

    // Take stock atomically; if anything is short, undo and flag the order for manual review/refund.
    const taken = [];
    let stockOk = true;
    for (const line of lines) {
        const result = await Product.updateOne(
            { _id: line.productId, countInStock: { $gte: line.quantity } },
            { $inc: { countInStock: -line.quantity } }
        );
        if (result.modifiedCount !== 1) { stockOk = false; break; }
        taken.push(line);
    }
    if (!stockOk) {
        await Promise.all(taken.map((l) => Product.updateOne({ _id: l.productId }, { $inc: { countInStock: l.quantity } })));
    }

    let order;
    try {
        order = await Orders.create({
            name: name.trim(),
            phoneNumber: phoneNumber.trim(),
            address: address.trim(),
            pincode: pincode.trim(),
            amount: String(total),
            paymentId: razorpay_payment_id,
            razorpayOrderId: razorpay_order_id,
            email: req.auth.email,
            userid: req.auth.id,
            products: lines,
            status: stockOk ? 'pending' : 'stock_issue',
        });
    } catch (err) {
        if (err.code === 11000) {
            const dup = await Orders.findOne({ paymentId: razorpay_payment_id });
            if (dup && dup.userid === req.auth.id) return res.status(200).json(dup);
        }
        throw err;
    }

    await Cart.deleteMany({ userId: req.auth.id });
    res.status(201).json(order);
}));

// ---------------------------------------------------------------------------
// Dashboards (admin only)
// ---------------------------------------------------------------------------

router.get('/sales', requireAdmin, handle(async (req, res) => {
    const year = parseInt(req.query.year, 10);
    const orders = await Orders.find().select('amount date');

    const monthlySales = MONTHS.map((month) => ({ month, sale: 0 }));
    let totalSales = 0;
    for (const order of orders) {
        const amount = parseInt(order.amount, 10) || 0;
        totalSales += amount;
        const date = new Date(order.date);
        if (date.getUTCFullYear() === year) monthlySales[date.getUTCMonth()].sale += amount;
    }
    res.status(200).json({ totalSales, monthlySales });
}));

router.get('/get/count', requireAdmin, handle(async (req, res) => {
    res.send({ orderCount: await Orders.countDocuments() });
}));

// ---------------------------------------------------------------------------
// Reading orders: customers see only their own; admins see all
// ---------------------------------------------------------------------------

router.get('/', requireAuth, handle(async (req, res) => {
    const filter = (await resolveAdmin(req)) ? req.query : { userid: req.auth.id };
    const orders = await Orders.find(filter).sort({ date: -1 });
    res.status(200).json(orders);
}));

router.get('/:id', requireAuth, handle(async (req, res) => {
    if (!isValidObjectId(req.params.id)) throw httpError(404, 'Order not found');
    const order = await Orders.findById(req.params.id);
    if (!order) throw httpError(404, 'The order with the given ID was not found.');
    if (order.userid !== req.auth.id && !(await resolveAdmin(req))) throw httpError(403, 'Forbidden');
    res.status(200).send(order);
}));

// ---------------------------------------------------------------------------
// Managing orders (admin only). Only the status can change: amounts, items and
// payment details are never editable after payment.
// ---------------------------------------------------------------------------

router.put('/:id', requireAdmin, handle(async (req, res) => {
    if (!isValidObjectId(req.params.id)) throw httpError(404, 'Order not found');
    const { status } = req.body;
    if (!ORDER_STATUSES.includes(status)) {
        throw httpError(400, `Status must be one of: ${ORDER_STATUSES.join(', ')}`);
    }
    const order = await Orders.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!order) throw httpError(404, 'Order not found');
    res.send(order);
}));

router.delete('/:id', requireAdmin, handle(async (req, res) => {
    if (!isValidObjectId(req.params.id)) throw httpError(404, 'Order not found');
    const deleted = await Orders.findByIdAndDelete(req.params.id);
    if (!deleted) throw httpError(404, 'Order not found!');
    res.status(200).json({ success: true, message: 'Order Deleted!' });
}));

module.exports = router;
