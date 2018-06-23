var mongoose = require('mongoose');
var bcrypt = require('bcrypt-node.js'); // encrypts password like abc123 --> 207349n42h3y482 
var Schema = mongoose.Schema;

/* The user schema attributes (fields)*/
var UserSchema = new mongoose.Schema({
    email : {type: String, unique: true, lowercase: true },
    password : String, 


    //full name 
    //last name

    profile: {
        name: {type: String, default: ''},
        picture: {type: String, default: ''}
    },

    address: String,
    history: [{
        date: Date,
        paid: {type: Number, default:0},
        // item: {type: mongoose.Schema.Types.ObjectId, ref:''}
    }]
});
 
/* Hash the password before saving to the database */
UserSchema.pre('save', function(next){
    var user = this;
    if(!user.isModified('password')) return next();
    bcrypt.genSalt(10, function(err, salt){
        //salt is the result of bcrypt
        if(err) return next(err);
        bcrypt.hash(user.password, salt, null, function(err, hash){
            if(err) return next(err);
            user.password = hash;
            next();
        }); 
    });
});

// UserSchema.pre('save', function(next){
//     var user = this;
//     user.name = "Dyam";
// });


/* Compare password in the database and the ne that the user type in */
UserSchema.methods.comparePassword = function(password){
    return bcrypt.compareSync(password, this.password);
};
