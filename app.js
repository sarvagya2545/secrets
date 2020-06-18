require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');
const session = require('express-session');
const bcrypt = require('bcryptjs');

// connecting to mongoose
mongoose.connect("mongodb://localhost:27017/userDB",  {useNewUrlParser:true, useUnifiedTopology:true, useCreateIndex:true})
.then( con => {
    console.log("DB connection Successful.");
})
.catch( err => {
    console.log(err);
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = new mongoose.model("User", userSchema);

// using passport localstrategy
passport.use(
    new LocalStrategy({ usernameField: 'email' }, (email,password,done) => {
        // Match User
        User.findOne({ email: email })
            .then(user => {
                if(!user) {
                    return done(null, false, { message: 'That email is not registered.' });
                }

                // If user found then check its password.
                bcrypt.compare(password, user.password, (err,isMatch) => {
                    if(err) throw err;

                    if(isMatch) {
                        return done(null, user);
                    } else {
                        return done(null, false, { message: 'Password incorrect' })
                    }
                });
            })
            .catch(err => console.log(err));
    })
);

// serialising and deserialising users
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

const app = express();

app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}));
app.set('view engine', 'ejs');

// using express-session
app.use(session({
    secret: 'Our little Secret.',
    resave: true,
    saveUninitialized: true
}));

// passport middleware
app.use(passport.initialize());
app.use(passport.session());

// flash middleware
app.use(flash());

// global variables
app.use((req,res,next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error =  req.flash('error');
    next();
});

var ensureAuthenticated = function(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }

    req.flash('error_msg', 'Please login to view this resource');
    res.redirect('/login');
}

app.get("/",function(req,res){
    res.render("home");
});

app.get('/secrets', ensureAuthenticated ,function(req,res){
    res.render('secrets');
})

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.post("/register", function(req,res){

    const { email, password } = req.body;

    let errors = [];

    // Check required fields
    if(!email || !password){
        errors.push({ msg: 'Please fill in all fields'});
    }

    // Check passwords length
    if(password.length < 6){
        errors.push({msg: 'Passwords length must be at least 6 characters'});
    }

    if(errors.length > 0) {
        res.render("register",{
            errors,
            email,
            password
        });
    } else {
        // Validation passed
        User.findOne({ email: email })
            .then(user => {
                if(user) {
                    errors.push({msg: 'Email is already registered.'});
                    res.render('register',{
                        errors,
                        email,
                        password
                    });
                } else {

                    const newUser = new User({
                        email,
                        password
                    });

                    // hash password
                    bcrypt.genSalt(10 , function(err,salt){
                        bcrypt.hash(newUser.password, salt, function(err, hash){
                            if(err) throw err;
                            newUser.password = hash;
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg' , 'You are now registered and can log in');
                                    res.redirect('/login');
                                })
                                .catch(err => console.log(err));
                        })
                    })

                }
            })
            .catch(err => console.log(err));
    }
});

app.post("/login", function(req,res,next){

    passport.authenticate('local', {
        successRedirect: '/secrets',
        failureRedirect: '/login',
        failureFlash: true
    })(req,res,next);
});

app.get('/logout', (req,res) => {
    req.logout();
    req.flash('success_msg', 'You are now logged out');
    res.redirect('/login');
});

app.listen(3000, function(){
    console.log("Successfully connected to port 3000.");
});
