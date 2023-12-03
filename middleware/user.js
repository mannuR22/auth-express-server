const logger =require('../utils/logger.js');
const jwt = require('jsonwebtoken');
const Auth = require('../models/auth.js');

const authenticate = async (req, res, next) => {
    let token = req.headers['x-access-token'] || req.headers['authorization']; 
    if (token && token.startsWith('Bearer ')) {
        logger.info("Token starts with Bearer")
        token = token.slice(7, token.length);
    }

    if (token) {

        try {
            const authDoc = await Auth.findOne({'token': token});
            if(!authDoc.isValid) return res.status(401,).json({
                message: "Invalid token"
            });
        }catch(e){
            logger.error('Error: ', e.message)
            return res.status(401,).json({
                message: "Invalid token",
                error: e.message
            });

        }
        jwt.verify(token, process.env.SECRET, (err, decoded) => {
            if (err) {
                logger.info('Token is not valid');
                return res.status(401).json({
                    message: "Invalid token"
                });
            } else {
                req.decoded = decoded;
                logger.info("Token Decoded Successfully", decoded)
                next();
            }
        });
    } else {
        logger.info('Auth token found Empty');
        return res.status(401).json({message:'Auth token is not provided'}) 
    }
};

module.exports = authenticate;



