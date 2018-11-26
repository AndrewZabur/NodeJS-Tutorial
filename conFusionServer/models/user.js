var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var passportLoccalMongoose = require('passport-local-mongoose');

var User = new Schema({
    admin: {
        type: Boolean,
        default: false
    }
});

User.plugin(passportLoccalMongoose);

module.exports = mongoose.model('User', User);