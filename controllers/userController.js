const User = require('../models/users');
const logger = require('../utils/logger');
const bcrypt = require('../utils/bcrypt');
const uuid = require('uuid4');
const auth = require('../models/auth');
const getDetails = async (req, res) => {
    logger.info("Get Users Details API gets called.")
    try {
        const userDoc = await User.findOne({ '_id': req.decoded.userId });
        logger.info("UserDoc: ", userDoc)
        code = 200;
        resBody = {
            message: "User info fetched successfully.",
            user: {
                name: userDoc.name,
                username: userDoc.username,
                bio: userDoc.bio,
                age: userDoc.age,
            },
        };
    } catch (e) {
        logger.error(e.message);
        code = 500;
        resBody = { messasge: "User doesnt Exist in DB." };
        return
    }
    res.status(code).json(resBody)

};

const updateInfo = async (req, res) => {
    logger.info("Update User Details API gets called.")
    let code, resBody;
    const { name, username, bio, age } = req.body;

    if (!name && !username && !bio && !age) {
        logger.error("Atleast one fields is required")
        code = 400;
        resBody = {
            message: 'Atleast one fields is required.'
        };

    } else {
        try {
            let filter = { '_id': req.decoded.userId }
            let update = {};

            if (username) {
                const userDocs = await User.find({ 'username': username });
                if (userDocs.length > 0) {
                    code = 409;
                    resBody = {
                        message: "username already exist, please choose different combination.",
                    };
                    return res.status(code).json(resBody);
                } else {
                    update.username = username;
                }
            }

            if (name) update.name = name;
            if (bio) update.bio = bio;
            if (age) update.age = age;


            await User.findOneAndUpdate(filter, update);
            let [updatedDoc] = await User.find(filter);
            code = 200;
            resBody = {
                message: "User info updated successfully.",
                updatedUser: {
                    name: updatedDoc.name,
                    username: updatedDoc.username,
                    bio: updatedDoc.bio,
                    age: updatedDoc.age,
                },
            };

        } catch (e) {
            logger.error(e.message);
            code = 500;
            resBody = {
                message: "Error occured while updating user doc.",
                error: e.message,
            }
        }
    }
    res.status(code).json(resBody);

};

const deleteInfo = async (req, res) => {
    let code, resBody;
    const userId = req.decoded.userId;
    const password = req.body.password;
    const currentTime = new Date();
    const expiresAt = new Date(currentTime.getTime() + Number(process.env.GRACE_MINS || '5') * 60 * 1000);
    try {
        const filter = { '_id': userId }
        const userDoc = await User.findOne(filter);
        await User.findOneAndUpdate(filter, { 'expiresAt': expiresAt })
        await auth.deleteMany({ userId: userId })
        if (bcrypt.validate(password, userDoc.password)) {
            code = 200;
            resBody = {
                message: "There is a grace Period of " + (process.env.GRACE_MINS || '5') + " mins, i.e., account will be invalidated/delted after (in GMT timezone) " + expiresAt.toUTCString() + ". In case you want to recover account try to login before grace period ends.",
                gracePeriodEnds: expiresAt.getTime()
            };
        } else {
            code = 409;
            resBody = {
                message: "Incorrect password!"
            };
        }


    } catch (e) {
        logger.error(e.message);
        code = 500;
        resBody = {
            message: "Error occured while fetching userDoc.",
            error: e.message,
        };
    }

    res.status(code).json(resBody);

};
module.exports = {
    getDetails,
    updateInfo,
    deleteInfo
};
