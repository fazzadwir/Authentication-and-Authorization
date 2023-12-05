import 'dotenv/config'
import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';

const app = express();
const port = 3000;
const PgSession = pgSession(session);

const db = new pg.Client({
    host: "localhost",
    user: "postgres",
    database: "userDB",
    password: "fazzadwir07",
    port: 5432
});

db.connect();

app.use(session({
    store: new PgSession({
        pool: db, // Use your PostgreSQL connection pool
        tableName: 'session',
    }),
    secret: 'Koloterorita',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }, // Set the session cookie expiration time
}));

const IV_LENGTH = 16;
const saltRounds = 5;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(process.env.ENCRYPTION_KEY, 'utf-8'), iv);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
}

function decrypt(text) {
    const iv = Buffer.from(text.slice(0, IV_LENGTH * 2), 'hex');
    const encryptedText = text.slice(IV_LENGTH * 2);
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(process.env.ENCRYPTION_KEY, 'utf-8'), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

//middleware
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({
    usernameField: 'username', // Assuming you use 'username' in your login form
    passwordField: 'password',
}, 
    async (username, password, done) => {
        try {
            const result = await db.query("SELECT * FROM userdb WHERE email = $1", [username]);
            if (result.rows.length === 0) {
                return done(null, false, { message: 'Incorrect username or password' });
            }

            const user = result.rows[0];
            const isValidPassword = await bcrypt.compare(password, user.password);

            if (!isValidPassword) {
                return done(null, false, { message: 'Incorrect username or password' });
            }

            return done(null, user);
        } catch (error) {
            return done(error);
        }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await db.query("SELECT * FROM userdb WHERE id = $1", [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (error) {
        done(error);
    }
});

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
    try {
        bcrypt.hash(req.body.password, saltRounds, async function(err, hash) {
            const newUsername = req.body.username;
            const encryptedPassword = hash;
    
            const checkUser = await db.query("SELECT * FROM userdb WHERE email = $1", [newUsername]);
            if (checkUser.rows.length > 0) {
                return res.status(409).json({ message: "User already registered" });
            }
    
            const result = await db.query(
                "INSERT INTO userdb (email, password) VALUES ($1, $2)", [newUsername, encryptedPassword]);
            res.render("secrets.ejs");
        });    
    } catch (error) {
        console.log("Error", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post("/login", passport.authenticate('local', {
    successRedirect: '/secrets',
    failureRedirect: '/login',
    failureFlash: true,
}));

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets.ejs");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
        }
        res.redirect("/");
    });
});


app.listen(port, () => {
    console.log("Server is running on port " + port);
});