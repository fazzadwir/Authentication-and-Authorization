import 'dotenv/config'
import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import crypto from 'crypto';
import session from 'express-session';
import passport from 'passport';
import passportLocal from 'passport-local';

const app = express();
const port = 3000;      

const db = new pg.Client({
    host: "localhost",
    user: "postgres",
    database: "userDB",
    password: "fazzadwir07",
    port: 5432
});

db.connect();
const LocalStrategy = passportLocal.Strategy;

passport.use(new LocalStrategy(
    { usernameField: 'email' }, // Assuming you use email as the username field
    async (email, password, done) => {
        // Your authentication logic with the database goes here
        // Example: Check if the email and password match a user in your database
        const user = await getUserByEmail(email);
        if (!user || !comparePasswords(password, user.password)) {
            return done(null, false, { message: 'Incorrect email or password' });
        }
        return done(null, user);
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await getUserById(id);
    done(null, user);
});

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our little babby.",
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
    res.render("home.ejs")
});


app.get("/login", (req,res) => {
    res.render("login.ejs");
});

app.get("/register", (req,res) => {
    res.render("register.ejs");
});

app.post("/register", async (req, res) => {

});

app.post("/login",  passport.authenticate('local', {
    successRedirect: '/', // Redirect to the home page on successful login
    failureRedirect: '/login', // Redirect to login page on failure
    failureFlash: true // Enable flash messages to show error messages
}));


app.listen(port, () => {
    console.log("Server is running on port " + port);
});

// Helper functions
async function getUserByEmail(email) {
    // Your database query to get a user by email goes here
}

async function getUserById(id) {
    // Your database query to get a user by ID goes here
}

function comparePasswords(password, hashedPassword) {
    // Your password comparison logic goes here
}