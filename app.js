import express from 'express';
import bodyParser from 'body-parser';
import ejs from 'ejs';;
import mongoose from 'mongoose';
import pg from 'pg';
import crypto from 'crypto';

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

function generateRandomKey() {
    return crypto.randomBytes(32).toString('hex');
};

const ENCRYPTION_KEY = generateRandomKey();
const IV_LENGTH = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + encrypted;
}

function decrypt(text) {
    const iv = Buffer.from(text.slice(0, IV_LENGTH * 2), 'hex');
    const encryptedText = text.slice(IV_LENGTH * 2);
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

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
        const newUsername = req.body.username;
        const newPassword = req.body.password;

        // Encrypt the password before storing it in the database
        const encryptedPassword = encrypt(newPassword);

        const checkUser = await db.query("SELECT * FROM userdb WHERE email = $1", [newUsername]);
        if (checkUser.rows.length > 0) {
            return res.status(409).json({ message: "User already registered" });
        }

        const result = await db.query(
            "INSERT INTO userdb (email, password) VALUES ($1, $2)", [newUsername, encryptedPassword]);
        res.render("secrets.ejs");
    } catch (error) {
        console.log("Error", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post("/login", async (req, res) => {
    const getUsername = req.body.username;
    const getPassword = req.body.password;

    try {
        const result = await db.query(
            "SELECT * FROM userdb WHERE email = $1", [getUsername]);

        if (result.rows.length === 0) {
            console.log(result.rows);
            return res.status(401).json({ message: "Wrong username or password" });
        }

        // Decrypt the stored password and compare it with the entered password
        const decryptedPassword = decrypt(result.rows[0].password);

        if (decryptedPassword === getPassword) {
            res.render("secrets.ejs");
        } else {
            res.redirect("login.ejs");
        }

    } catch (error) {
        console.error("Error executing query", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


app.listen(port, () => {
    console.log("Server is running on port " + port);
});