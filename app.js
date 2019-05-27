// ============
// REQUIRE VARS
// ============
var express = require("express"),
    app = express(),
    mongoose = require("mongoose"),
    passport = require("passport"),
    bodyParser = require("body-parser"),
    LocalStrategy = require("passport-local"),
    passportLocalMongoose = require("passport-local-mongoose"),
    User = require("./models/user");

// =============
// APP CONFIGURE
// =============
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
mongoose.connect("mongodb://localhost/secretApp", { useNewUrlParser: true });


// Require & use express-session in the same line
app.use(require("express-session")({
    // Secret is arbitrary & is used to encode & decode the sessions. 
    secret: "This is a secret",
    resave: false,
    saveUninitialized: false
}));

// ===============
// PASSPORT SET UP 
// ===============
app.use(passport.initialize());
app.use(passport.session());

// Use the local strategy that comes from the line we defined in our User Model file
// This later gets called as middleware in our post route for user log in
passport.use(new LocalStrategy(User.authenticate()));

// Responsible for encoding the data and putting it back in the session
passport.serializeUser(User.serializeUser());
// Responsible for unencoding the data from the session
passport.deserializeUser(User.deserializeUser());

// ========
// ROUTES 
// ========
app.get("/", (req, res) => {
    res.render("home");
});

// isLoggedIn function added as middleware & allows user to reach /secret 
// only if a user is logged in
app.get("/secret", isLoggedIn, (req, res) => {
    res.render("secret");
});

// ===========
// AUTH ROUTES
// ===========
app.get("/register", (req, res) => {
    res.render("register");
})

app.post("/register", (req, res) => {
    // User.register takes TWO arguments, one is a new user object with the username passed in from the form
    // the password is passed in as a second argument and is hashed & stored in the database, as opposed to
    // storing the password in the db itself. 
    User.register(new User({ username: req.body.username }), req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            return res.render("/register");
        }
        // This line will log the user in, take care of session data, run the serialize user method
        // using the local strategy
        passport.authenticate('local')(req, res, () => {
            res.redirect("/secret");
        });
    });
});

// ===========
// LOGIN ROUTES
// ===========

app.get("/login", (req, res) => {
    res.render("login");
})

// This post route takes middleware code that automatically tries to log the user in
app.post("/login", passport.authenticate('local', {
    successRedirect: '/secret',
    failureRedirect: '/login'
}), (req, res) => {
    // Nothing needed in this callback function for now..
});

// Log user out when this route is reached
app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
})

// Middleware code to check if a user is logged in, used at the /secret route
function isLoggedIn(req, res, next) {
    // .isAuthenticated() comes from passport
    if(req.isAuthenticated()){
        // next is the next set of code that will be called
        return next();
    }
    res.redirect("/login");
}


app.listen(3000, () => console.log("Server is listening..."));