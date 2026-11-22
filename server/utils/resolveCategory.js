const { Category } = require('../models/category');

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Finds a category (or sub category, when parentId is given) by name, ignoring case.
// Creates it if it does not exist yet, so admins can simply type the name.
async function findOrCreateByName(name, parentId) {
    const clean = String(name || '').trim();
    if (!clean) return null;

    const existing = await Category.findOne({
        name: new RegExp(`^${escapeRegex(clean)}$`, 'i'),
        parentId: parentId ? String(parentId) : { $in: [null, ''] },
    });
    if (existing) return existing;

    // `slug` must be unique; add a number if the name is already used elsewhere.
    let slug = clean;
    let n = 1;
    while (await Category.exists({ slug })) slug = `${clean}-${++n}`;

    return Category.create({
        name: clean,
        slug,
        ...(parentId ? { parentId: String(parentId) } : {}),
    });
}

// Accepts either an existing category id (old behaviour) or typed names (catName / subCat).
async function resolveCategory(body) {
    let category = null;
    if (body.category && /^[a-fA-F0-9]{24}$/.test(String(body.category))) {
        category = await Category.findById(body.category);
    }
    if (!category) category = await findOrCreateByName(body.catName);
    if (!category) return null;

    let subCategory = null;
    const subName = body.subCatName || body.subCat;
    if (body.subCatId && /^[a-fA-F0-9]{24}$/.test(String(body.subCatId))) {
        subCategory = await Category.findById(body.subCatId);
    }
    if (!subCategory && subName && String(subName).trim()) {
        subCategory = await findOrCreateByName(subName, category._id);
    }
    return { category, subCategory };
}

module.exports = { resolveCategory, findOrCreateByName };
