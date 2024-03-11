function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        req.user = req.session.user; // Make user data available in the request
        next();
    } else {
        console.error('Unauthorized: No valid session');
        return res.status(401).send('Unauthorized: No valid session');
    }
}

module.exports = isAuthenticated;
