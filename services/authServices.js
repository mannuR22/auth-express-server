const jwt = require('jsonwebtoken');
const users = require('../models/users');
const logger = require('../utils/logger');
const register = (req, res) => {
    logger.info()

    // Return confirmation and user details
    res.json({
        message: 'Account created successfully',
        user: {
            id: newUser.id,
            name: newUser.name,
            username: newUser.username,
            bio: newUser.bio,
            age: newUser.age,
        },
    });
};


const loginn = (req, res) => {
    User.findOne({ email: req.body.email }, function (err, user) {
        if (err) {
            console.log(err)
            return res.status(401).json({
                message: "Auth failed"
            });
        }
        if (!user) {
            console.log("No user found.")
            res.status(401).json({
                message: "Auth failed"
            });
        }
        if (!user.validPassword(req.body.password)) {
            req.flash('error', 'Wrong password');
            res.status(401).json({
                message: "Auth failed"
            });
        }
        if (user) {
            console.log("logged in")
            const token = jwt.sign(
                {
                    email: user.email,
                    userId: user._id
                },
                process.env.SECRET,
                {
                    expiresIn: "12h"
                }
            );
            return res.status(200).json({
                message: "Auth successful",
                token: token,
                uid: user._id
            });
        }
    }).catch(err => {
        console.log(err);
        res.status(500).json({
            error: err
        });
    });
}
const login = async (req, res) => {
    const { name, username, bio, age, password } = req.body;

    if (!username || !password) {
        logger.info('username and password required, RequestBody', req.body);
        return res.send(400, 'username and password required.');
    }
    // Check if User Exist with username

    try {
        const userDoc = await user.findOne({ 'username': username });

        if (bcrypt.validate(password, userDoc.password)) {
            logger.Info("User Verified with username: ", username);

            if (userDoc) {
                
                const token = jwt.sign(
                    {
                        email: user.email,
                        userId: user._id
                    },
                    process.env.SECRET,
                    {
                        expiresIn: "12h"
                    }
                );

                logger.info("token for user")
                return res.send(200).json({
                    message: "Auth successful",
                    token: token,
                    uid: userDoc._id
                });
            }
        } else {
            logger.error("User Password Mis-Incorrect.");
            res.send(401, "Incorrect-Password");
        }
    } catch (error) {
        logger.info("User doesnt Exist with username: " + username + ", Error: " + error.message)

    }
    // User.findOne({ email: req.body.email }, function (err, user) {
    //     if (err) {
    //         console.log(err)
    //         return res.status(401).json({
    //             message: "Auth failed"
    //         });
    //     }
    //     if (!user) {
    //         console.log("No user found.")
    //         res.status(401).json({
    //             message: "Auth failed"
    //         });
    //     }
    //     if (!user.validPassword(req.body.password)) {
    //         req.flash('error', 'Wrong password');
    //         res.status(401).json({
    //             message: "Auth failed"
    //         });
    //     }
    //     if (user) {
    //         console.log("logged in")
    //         const token = jwt.sign(
    //             {
    //                 email: user.email,
    //                 userId: user._id
    //             },
    //             process.env.SECRET,
    //             {
    //                 expiresIn: "12h"
    //             }
    //         );
    //         return res.status(200).json({
    //             message: "Auth successful",
    //             token: token,
    //             uid: user._id
    //         });
    //     }
    // }).catch(err => {
    //     console.log(err);
    //     res.status(500).json({
    //         error: err
    //     });
    // });
    // if (!name || !username || !bio || !age || !password) {
    //     logger.info("All fields are required. Request Body", req.body)
    //     return res.status(400).json({ error: 'All fields are required' });
    // }
    // // Find the user by username (replace this with a database query)
    // const user = users.find((u) => u.username === username);

    // // Check if the user exists and the password is correct (replace this with proper authentication)
    // if (!user || user.password !== password) {
    //     return res.status(401).json({ error: 'Invalid username or password' });
    // }

    // // Generate and return an authentication token
    // const token = jwt.sign({ userId: user.id }, 'your-secret-key', { expiresIn: '1h' });

    // Return authentication token and user details

};

module.exports = {
    register,
    login,
};
