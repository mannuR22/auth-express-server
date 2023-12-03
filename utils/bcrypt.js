var bcrypt = require("bcrypt");

const encrypt = (password) => {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10), null);
};

const validate = (actual, encrypted) => {
    return bcrypt.compareSync(actual, encrypted);
};

module.exports = { encrypt, validate}