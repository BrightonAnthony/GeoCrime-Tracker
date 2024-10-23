const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const path = require('path');
const http = require('http');
const bcrypt = require('bcryptjs');
const multer = require('multer');


// // Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, 'public')));
// Middleware to parse the incoming form data

// Allow cross-origin requests
app.use(cors({
    origin: '*',  // Allow requests from your form's origin
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


// Connect to MySQL database
// const db = mysql.createConnection({
//     host: 'localhost',
//     user: 'brighton',   // Your MySQL username
//     password: 'bri123',   // Your MySQL password
//     database: 'geocrime_tracker'  // Your database name
// });

const db = mysql.createPool({
    host: 'localhost',
    user: 'brighton',
    password: 'bri123',
    database: 'geocrime_tracker',
    waitForConnections: true,
    connectionLimit: 10,  // Number of connections in pool
    queueLimit: 0
});


// db.connect(err => {
//     if (err) {
//         console.log('Error connecting to MySQL:', err);
//     } else {
//         console.log('Connected to MySQL');
//     }
// });

// Handle form submission
app.post('/submit', (req, res) => {
    console.log('Request received for /submit');
    console.log('Form data:', req.body);
    // console.log(req.body); // Log the received data to check
    const {
        polog_pid,
        polog_pname,

        polog_crimetype,
        polog_crimedesc,
        polog_loc,
        polog_lat,
        polog_lng,
        polog_date,
        polog_time,

        polog_vname,
        polog_vphone,
        polog_vaddress,

        polog_cadhaarnum,
        polog_cid,
        polog_cname,
        
        
    } = req.body;

    // Handle empty fields for aadhaar and other numeric fields
    const description = polog_crimedesc === '' ? null : polog_crimedesc;
    const aadhaar = (!polog_cadhaarnum || polog_cadhaarnum === '') ? null : polog_cadhaarnum;
    const cid = (!polog_cid || polog_cid === '') ? null : polog_cid;
    const cname = (!polog_cname || polog_cname === '') ? null : polog_cname;

    // const latitude = polog_lat ==='' ? null : polog_lat;
    // const longitude = polog_lng ==='' ? null : polog_lng;

    const sql = 'INSERT INTO policeregistration (police_id, police_name, crime_type, crime_dec,location, latitude, longitude, date, time,victim_name, victim_no , victim_add , criminal_aadhaar, criminal_id, criminal_name ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    db.query(sql, [polog_pid, polog_pname, polog_crimetype,description, polog_loc, polog_lat, polog_lng,polog_date, polog_time , polog_vname,polog_vphone,polog_vaddress, aadhaar, cid, cname ], (err, result) => {
        if (err) {
            console.log('Error inserting data:', err);
            return res.status(500).json({ message: 'Failed to register crime' });
        } else {
            return res.status(200).json({ message: 'Crime registered successfully!' });
        }
    });
});

// Handle criminal Aadhaar number check
app.post('/check-criminal', (req, res) => {
    const aadhaarNumber = req.body.aadhaar;
    console.log('Received Aadhaar Number:', aadhaarNumber); // Log the Aadhaar number

    const sql = 'SELECT criminal_id, criminal_name FROM policeregistration WHERE criminal_aadhaar = ?';
    db.query(sql, [aadhaarNumber], (err, results) => {
        if (err) {
            console.log('Error checking criminal:', err);
            return res.status(500).json({ error: 'Server error' });

        }
        console.log('SQL Results:', results); // Log the results from the query
        if (results.length > 0) {
            // Criminal found
            res.json({
                found: true,
                id: results[0].criminal_id,   // Make sure to reference criminal_id
                name: results[0].criminal_name
            });
        } else {
            // Criminal not found
            res.json({ found: false });
        }
    });
});


// Serve the form
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/policeForm.html');
});





// Handle signup form submission with password hashing
app.post('/signup', (req, res) => {
    const { name, email, password, confirm_password } = req.body;

    // Check if passwords match
    if (password !== confirm_password) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    // Check if email already exists in the database
    const checkEmailSql = 'SELECT * FROM users WHERE email = ?';
    db.query(checkEmailSql, [email], (err, results) => {
        if (err) {
            console.log('Error checking email:', err);
            return res.status(500).json({ message: 'Server error' });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        // Hash the password before storing
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.log('Error hashing password:', err);
                return res.status(500).json({ message: 'Server error' });
            }

            // If email is not in use, insert new user into the database
            const insertUserSql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
            db.query(insertUserSql, [name, email, hash], (err, result) => {
                if (err) {
                    console.log('Error inserting user:', err);
                    return res.status(500).json({ message: 'Failed to register user' });
                }

                // Send a success message and a redirect URL to login page
                return res.status(200).json({ message: 'User registered successfully!', redirect: '/login.html' });
            });
        });
    });
});


// Login Route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    // Check if user exists in the database
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ message: 'Server error' });
        }

        if (results.length === 0) {
            // No user found with the provided email
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = results[0];

        // Compare the provided password with the hashed password in the database
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ message: 'Server error' });
            }

            if (!isMatch) {
                // Password does not match
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            // Authentication successful
            return res.status(200).json({ message: 'Login successful', redirect: '/CrimeMonitoring.html' });
        });
    });
});



//public form from phone
// Set up storage engine for multer (to handle file uploads)
const storage = multer.diskStorage({
    destination: './uploads',  // Adjust this path for your project
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Add timestamp to filename
    }
});

const upload = multer({ storage: storage }).single('video'); // Handling video upload

app.post('/submit-crime', (req, res) => {
    upload(req, res, (err) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to upload video' });
        }

        const { name, phoneNo, crimeType, latitude, longitude, date, time, address } = req.body;
        const videoPath = req.file ? req.file.filename : null;

        const insertCrimeSql = `INSERT INTO publicregistration (name, phone_no, crime_type, video, latitude, longitude, date, time, location)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        db.query(insertCrimeSql, [name, phoneNo, crimeType, videoPath, latitude, longitude, date, time, address], (err, result) => {
            if (err) {
                console.log('Error inserting crime report:', err);
                return res.status(500).json({ message: 'Server error' });
            }

            return res.status(200).json({ success: true, message: 'Crime reported successfully!' });
        });
    });
});









// Start the server and bind it to 0.0.0.0 to allow access from other devices on the network
app.listen(3000, '0.0.0.0', () => {
    console.log('Server running at http://0.0.0.0:3000/');
});


//      http://localhost:3000/
//      node server.js
//      C:\Users\princy\Desktop\ngrok-v3-stable-windows-amd64\ngrok.exe http 3000