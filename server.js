const express = require('express');
const app = express();
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require("passport");
const flash = require('connect-flash'); // Flash middleware for displaying errors

const initializePassport = require("./passportConfig");

initializePassport(passport);

const PORT = process.env.PORT || 4000;

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Middleware to parse form data
app.use(express.urlencoded({ extended: false }));

// Session configuration
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));

// Initialize Passport and session handling
app.use(passport.initialize());
app.use(passport.session());

// Flash messages
app.use(flash());

// Global variables for flash messages
app.use((req, res, next) => {
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

// Home route
app.get("/", (req, res) => {
    res.render("index");
});

// Registration form
app.get("/users/register", checkAuthenticated, (req, res) => {
    res.render("register");
});

// Login form
app.get("/users/login",checkAuthenticated, (req, res) => {
    res.render("login");
});

// Dashboard route
app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
    res.render("dashboard");
});


// Logout route
app.get('/users/logout', (req, res) => {
    req.logout((err) => { // Pass a callback to handle errors if any
        if (err) {
            console.error(err);
            return res.redirect('/users/dashboard'); // Redirect back to the dashboard on error
        }
        res.redirect('/users/login'); // Redirect to login after successful logout
    });
});

// Handle registration POST request
app.post("/users/register", async (req, res) => {
    let { name, email, password, password2 } = req.body;
    let errors = [];

    // Validation checks
    if (!name || !email || !password || !password2) {
        errors.push({ message: "Enter all the fields!" });
    }
    if (password !== password2) {
        errors.push({ message: "Password and Confirm Password do not match!" });
    }
    if (password.length < 6) {
        errors.push({ message: "Password should be more than 6 characters long!" });
    }

    // If errors, re-render the registration form with error messages
    if (errors.length > 0) {
        return res.render("register", { errors });
    } else {
        // Hash the password
        try {
            let hashedPassword = await bcrypt.hash(password, 10);
            console.log(hashedPassword);

            // Check if user already exists
            pool.query('SELECT * FROM users WHERE email = $1', [email], (err, results) => {
                if (err) {
                    throw err;
                }

                if (results.rows.length > 0) {
                    errors.push({ message: 'User Already Exists.' });
                    return res.render('register', { errors });
                } else {
                    // Insert the new user into the database
                    pool.query(
                        'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, password',
                        [name, email, hashedPassword],
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash('success_msg', 'You are now registered. Please log in.');
                            return res.redirect('/users/login');
                        }
                    );
                }
            });
        } catch (err) {
            console.error(err);
            return res.render("register", { errors: [{ message: "An error occurred during registration" }] });
        }
    }
});

// Handle login POST request using Passport
app.post("/users/login", passport.authenticate('local', {
    successRedirect: "/users/dashboard",
    failureRedirect: '/users/login',
    failureFlash: true
}));



function checkAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return res.redirect("/users/dashboard");
    }
    next();


}

function checkNotAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return next();
    }
   res.redirect("/users/login");
}
// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});