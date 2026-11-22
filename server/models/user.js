const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    phone:{
        type:String,
    },
    email:{
        type:String,
        required:true,
    },
    password:{
        type:String,
    },
    images:[
        {
            type:String,
            required:true
        }
    ],
    isAdmin:{
        type: Boolean,
        default: false,
    },
    isVerified:{
        type:Boolean,
        default:false
    },
    otp:{
        type:String
    },
    otpExpires:{
        type:Date
    },
    date: {
        type: Date,
        default: Date.now
    },
},{timestamps:true})

userSchema.virtual('id').get(function () {
    return this._id.toHexString();
});

userSchema.set('toJSON', {
    virtuals: true,
    // Never send credentials or one-time codes to any client.
    transform: (doc, ret) => {
        delete ret.password;
        delete ret.otp;
        delete ret.otpExpires;
        return ret;
    },
});

exports.User = mongoose.model('User', userSchema);
exports.userSchema = userSchema;
