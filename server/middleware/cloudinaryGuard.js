// Stops image uploads early with a clear message when Cloudinary keys are missing,
// instead of letting the request hang.
module.exports = function requireCloudinary(req, res, next) {
    const missing = ['cloudinary_Config_Cloud_Name', 'cloudinary_Config_api_key', 'cloudinary_Config_api_secret']
        .filter((k) => !process.env[k]);
    if (missing.length) {
        return res.status(503).json({
            success: false,
            msg: `Image uploads are not configured. Set ${missing.join(', ')} in server/.env and restart the server.`,
        });
    }
    return next();
};
