const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const passport = require('passport')
const passportLocal = require('passport-local')
const session = require('express-session')

const app = express();

const bodyParser = require('body-parser');

const mysql = require('mysql');
const bcrypt = require('bcrypt');
const cors = require('cors')

app.use(cors())




const { log } = require('console');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const PORT = process.env.PORT; // or any port you prefer

app.use(session({
    secret: "top-secret",
    resave: false,
    saveUninitialized: true,
}))

const db =  mysql.createConnection({
    host: 'localhost',  
    user: 'root',  
    password: '',  
    database: 'db_mssn'
})

db.connect((err)=>{
    if (err) {
        throw err;
    }

    log("Connected to MySQL database")
})

// Middleware to serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route for serving the login form
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route for serving the registration form
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});



app.post('/login', async (req, res)=>{
    const { email, password} = req.body
    const user =  { email, password };

    try{

        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results)=>{
            if (err){
                console.log('Error retreiving user:', err);
                return res.status(500).json({message: 'Internal server error'})
    
            }
    
            if(results.length === 0){
                return res.status(401).json({message: 'Invalid email or password'})
            }
    
            const user = results[0]
            const passwordMatch = await bcrypt.compare(password, user.password);
    
            if (!passwordMatch) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            const secretKey = crypto.randomBytes(32).toString('hex');
    
            // If password is correct, create a JWT token
            const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '5m' });
            
            res.status(200).json({ message: 'Login successful', token });

    
        })
    }catch(error){
        log('Error logging in user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }

    
})


app.post('/register', async (req, res) => {
    const { firstname, lastname, matric_no, level, email, password } = req.body;

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the saltRounds

        // Create a new user object with the hashed password
        const newUser = {
            firstname,
            lastname,
            matric_no,
            level,
            email,
            // Store the hashed password, not the plaintext password
            password: hashedPassword
        };
        // console.log(newUser)
        // Insert the user into the database
        db.query('INSERT INTO users SET ?', newUser, (err, result) => {
            if (err) {
                console.error('Error registering user: ', err);
                return res.status(500).json({ message: 'Error registering user' });
            }

            console.log('User registered successfully');
            console.log('Inserted ID:', result.insertId);
            res.status(200).json({ message: 'User registered successfully' });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Error hashing password' });
    }
});




// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
