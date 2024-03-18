function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        console.error('Unauthorized: No valid session');
        return res.status(401).send('Unauthorized: No valid session');
    }
}

module.exports = isAuthenticated;
