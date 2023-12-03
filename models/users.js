// In-memory storage for user data (replace this with a database in a real application)
const mongoose = require('mongoose');

var userSchema = new mongoose.Schema({
    _id: String,
    name: String,
    username: String,
    password: String,
    bio: String,
    age: Number,
    createdAt: {
        type: Number,
        default: Date.now(),
    },
    expiresAt: {
        type: Date,
    }
});
userSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
module.exports = mongoose.model("Users", userSchema, "Users");
