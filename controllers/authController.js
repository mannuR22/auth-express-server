const jwt = require('jsonwebtoken');
const User = require('../models/users');
const logger = require('../utils/logger');
const bcrypt = require('../utils/bcrypt');
const uuid = require('uuid4');
const Auth = require('../models/auth')

const register = async (req, res) => {
    const { name, username, bio, age, password } = req.body;

    if (!name || !username || !bio || !age || !password) {
        logger.info("All fields are required. Request Body", req.body)
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const user = new User();
        // const userDoc = await user.findOne();
        const userDoc = await User.find({ 'username': username });
        if (userDoc.length > 0) {
            return res.status(409).json({ message: "username already exist." })
        } else {
            user._id = uuid();
            user.username = username;
            user.name = name;
            user.password = bcrypt.encrypt(password);
            user.age = age
            user.bio = bio;

            user.save();


            res.send(201, {
                message: "User created Successfully.",
                userInfo: {
                    name: user.name,
                    username: user.username,
                    age: user.age,
                    bio: user.bio,
                }
            });
        }

    } catch (e) {
        console.log(e)
        res.status(500).json({
            message: "An error has occured."
        })
    }
};

const login = async (req, res) => {
    const { username, password } = req.body;
    let recoveryMsg = '', code, resBody;
    if (!username || !password) {
        logger.info('username and password required, RequestBody', req.body);
        code = 400
        resBody = { message: 'username and password required.' }
    } else {
        try {

            const userDoc = await User.findOne({ 'username': username });

            if (bcrypt.validate(password, userDoc.password)) {

                logger.info("User Verified with username: ", username);
                const token = jwt.sign(
                    {
                        userId: userDoc._id
                    },
                    process.env.SECRET,
                    {
                        expiresIn: "12h"
                    }
                );
                //creating auth doc in mongo
                const auth = new Auth();
                auth._id = uuid();
                auth.token = token;
                auth.isValid = true;
                auth.userId = userDoc._id;
                auth.save();
                logger.info("Auth doc inserted successfully.")
                if (userDoc['expiresAt']) {
                    logger.info("Accound under Grace Period.")
                    recoveryMsg = "Account recovered successfully."
                    userDoc.expiresAt = undefined;
                    userDoc.save();
                }
                logger.info("Auth Successful, Token:", token)
                code = 200;
                resBody = {
                    message: recoveryMsg != '' ? recoveryMsg : "Auth successful",
                    token: token
                };

            } else {
                logger.error("User Password Mis-Incorrect.");
                code = 401;
                resBody = {
                    message: "Incorrect password!"
                };
            }
        } catch (e) {
            logger.error(e.message, "username: " + username)
            code = 409;
            resBody = {
                message: "User doesn't exist with username.",
                error: e.message,
            };
        }
    }

    res.status(code).json(resBody);


};

const logout = async (req, res) => {
    let token = req.headers['x-access-token'] || req.headers['authorization'];
    if (token.startsWith('Bearer ')) {
        logger.info("Token starts with Bearer")
        token = token.slice(7, token.length);
    }

    if (token) {
        try {
            const authDoc = await Auth.findOneAndUpdate({ 'token': token }, { isValid: false })

            return res.status(200).json({
                message: "User logout success."
            })
        } catch (e) {
            logger.error("Error: ", e.message)
            return res.status(409).json({
                message: "Error Occured while feteching authDoc from auths collection.",
                error: e.message
            })
        }
    }

}

const passwordReset = async (req, res) => {

    const { username, currentPassword, newPassword } = req.body;
    let resBody = {}, code;
    if (!currentPassword || !newPassword) {
        logger.error("currentPassword and newPassword field required.")
        code = 403;
        resBody = {
            message: "currentPassword and newPassword field required."
        };
    } else {
        if (req.hasOwnProperty('decoded')) {
            const userId = req.decoded.userId;
            try {
                const userDoc = await User.findOne({ _id: userId });

                if (bcrypt.validate(currentPassword, userDoc.password)) {
                    await User.findOneAndUpdate({ _id: userId }, { password: bcrypt.encrypt(newPassword) });
                    logger.info("Password updated successfully.");
                    code = 201;
                    resBody = {
                        message: "Password updated successfully."
                    }
                } else {
                    logger.error("In-correct current-password entered.");
                    code = 409;
                    resBody = {
                        message: "Incorrect current-Password entered."
                    };
                }
            } catch (e) {
                logger.error(e.message);
                code = 409;
                resBody = {
                    message: "user doesnt Exist in db.",
                    error: e.message
                };
            }
        } else {
            if (!username) {
                logger.error("username field is also required, in case of reseting password without auth-token.")
                code = 403;
                resBody = {
                    message: "username field is also required, in case of reseting password without auth-token."
                }
            } else {
                try {
                    const userDoc = await User.findOne({ 'username': username });

                    if (bcrypt.validate(currentPassword, userDoc.password)) {
                        await User.findOneAndUpdate({ 'username': username }, { password: bcrypt.encrypt(newPassword) });
                        logger.error("Password updated successfully.");
                        code = 201;
                        resBody = {
                            message: "Password updated successfully."
                        };
                    } else {
                        logger.info("In-correct current-password entered.");
                        code = 409;
                        resBody = {
                            message: "Incorrect current-Password entered."
                        };
                    }
                } catch (e) {
                    logger.error(e.message)
                    code = 409;
                    resBody = {
                        message: "user doesnt exist with username.",
                        error: e.message,
                    }
                }
            }
        }
    }

    res.status(code).json(resBody);

}

module.exports = {
    register,
    login,
    logout,
    passwordReset
};
