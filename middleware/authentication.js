const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
    const token = req.header('Authorization');

    if(!token) {
        res.status(403).send({'error': 'not authorized'});
    }
    
    try {
        const verifiedToken = jwt.verify(token, process.env.JWT_SECRET);

        req.user = verifiedToken;
        next();
    } catch (e) {
        res.status(401).send({error: 'not auth'});
    }
}

module.exports = auth;