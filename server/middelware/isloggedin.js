const User = require('../models/user');
const jwt = require('jsonwebtoken');

const key = process.env.JWT;

const isloggedin = async (req, res, next) => {
    try {
        if (!key) {
            console.error("Auth Error: JWT secret not configured");
            return res.status(500).json({ message: "Server configuration error" });
        }
        if (!req.cookies || !req.cookies.token) {
            return res.status(401).json({ message: "You must login first" });
        }

        const data = jwt.verify(req.cookies.token, key);

        const user = await User.findOne({ email: data.email });

        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        req.user = user;
        next();

    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: "Session expired. Please login again" });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: "Invalid token" });
        }
        console.log("Auth Error:", err.message);
        return res.status(401).json({ message: "Invalid or expired token" });
    }
};

module.exports = isloggedin;
