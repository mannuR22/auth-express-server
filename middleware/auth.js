const jwt = require('jsonwebtoken');
const Auth = require('../models/auth.js');
const logger =require('../utils/logger.js');

const authMiddleware = async (req, res, next) => {
    logger.info("Middleware Called")
    let token = req.headers['x-access-token'] || req.headers['authorization']; 
    if (token && token.startsWith('Bearer ')) {
        logger.info("Token starts with Bearer")
        token = token.slice(7, token.length);
    }

    if (token) {
        let isValid = false;
        try {
            const authDoc = await Auth.findOne({'token': token});
            isValid = authDoc.isValid;
        }catch(e){
            logger.error('Error: ', e.message)
        }

        if(isValid){
            jwt.verify(token, process.env.SECRET, (err, decoded) => {
                if (!err) {
                    req.decoded = decoded;
                    logger.info("Token Decoded Successfully", decoded)   
                }
            });
        }
        
    }

    next();
};

module.exports  = authMiddleware;
