const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const path = require('path');
const http = require('http');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
require('dotenv').config(); // Load environment variables
const twilio = require('twilio');
const nodemailer = require('nodemailer');
const dns = require('dns');
const { promisify } = require('util');
const resolveMx = promisify(dns.resolveMx);
const { PythonShell } = require('python-shell');
const { spawn } = require("child_process");

// Initialize Twilio client
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;


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
    connectionLimit: 50,  // Number of connections in pool
    queueLimit: 0
});





// Set up Multer for file uploads
const storage_photo = multer.diskStorage({
    destination: './uploads/photos',  // Adjust this path for your project
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Add timestamp to filename
    }
});

const upload_photo = multer({ storage: storage_photo }).single('criminal_photo');

// Handle form submission
app.post('/submit', (req, res) => {
    upload_photo(req, res, (err) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to upload Photo' });
        }
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

    let photoFilename = null;

    if (req.file) {
        photoFilename = req.file.filename; // New photo uploaded
    } else if (Array.isArray(req.body.criminal_photo)) {
        photoFilename = req.body.criminal_photo.find(filename => filename !== 'undefined') || null;
    } else if (req.body.criminal_photo && req.body.criminal_photo !== 'undefined') {
        photoFilename = req.body.criminal_photo;
    }
    
    const sql = 'INSERT INTO policeregistration (police_id, police_name, crime_type, crime_dec,location, latitude, longitude, date, time, victim_name, victim_no , victim_add , criminal_aadhaar,criminal_photo, criminal_id, criminal_name ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

    db.query(sql, [polog_pid, polog_pname, polog_crimetype,description, polog_loc, polog_lat, polog_lng,polog_date, polog_time , polog_vname,polog_vphone,polog_vaddress, aadhaar,photoFilename, cid, cname ], (err, result) => {
        if (err) {
            console.log('Error inserting data:', err);
            return res.status(500).json({ message: 'Cannot register a crime without logging in.' });
        } else {
            return res.status(200).json({ message: 'Crime registered successfully!' });
        }
    });
});
});



app.use('/uploads', express.static('uploads'));

// Handle criminal Aadhaar number check
app.post('/check-criminal', (req, res) => {
    const aadhaarNumber = req.body.aadhaar;
    console.log('Received Aadhaar Number:', aadhaarNumber); // Log the Aadhaar number

    const sql = 'SELECT criminal_photo, criminal_id, criminal_name FROM policeregistration WHERE criminal_aadhaar = ?';
    db.query(sql, [aadhaarNumber], (err, results) => {
        if (err) {
            console.log('Error checking criminal:', err);
            return res.status(500).json({ error: 'Server error' });

        }
        console.log('SQL Results:', results); // Log the results from the query
        if (results.length > 0) {
            // Criminal found
            const photoFilename = results[0].criminal_photo;
            const photoPath = photoFilename
                ? `/uploads/photos/${photoFilename}` // Full URL
                : null;
            res.json({
                found: true,
                photo: photoPath, // Return full URL
                id: results[0].criminal_id,
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



const signupOtpStorage = new Map(); // Store signup OTPs temporarily

app.post('/send-signup-otp', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    // Check if email is already registered
    const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(checkEmailQuery, [email], async (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ success: false, message: 'Server error. Try again later.' });
        }

        if (results.length > 0) {
            return res.status(400).json({ success: false, message: 'This email is already registered.' });
        }

        // Extract domain from email (e.g., 'gmail.com' from 'test@gmail.com')
        const domain = email.split('@')[1];

        try {
            const mxRecords = await resolveMx(domain);

            if (!mxRecords || mxRecords.length === 0) {
                return res.status(400).json({ success: false, message: 'Invalid email address. Please enter a valid email.' });
            }
        } catch (error) {
            return res.status(400).json({ success: false, message: 'Invalid email domain. Please enter a valid email.' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        signupOtpStorage.set(email, otp); // Store OTP temporarily

        // Send OTP via email
        const mailOptions = {
            from: 'brightonanthonybusiness@gmail.com',
            to: email,
            subject: 'Signup OTP Verification',
            text: `Your OTP for signup verification is: ${otp}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending OTP:', error);
                return res.status(500).json({ success: false, message: 'Failed to send OTP. Please check your email address.' });
            }
            res.json({ success: true, message: 'OTP sent to your email.' });
        });
    });
});



app.post('/verify-signup-otp', (req, res) => {
    const { email, otp } = req.body;

    if (!signupOtpStorage.has(email) || signupOtpStorage.get(email) != otp) {
        return res.status(400).json({ success: false, message: 'Invalid OTP.' });
    }

    signupOtpStorage.delete(email); // Remove OTP after verification
    res.json({ success: true, message: 'OTP verified successfully!' });
});


// Configure session middleware
app.use(session({
    secret: process.env.secret,
    resave: false,
    saveUninitialized: true
}));


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

            // Save user info in session
            req.session.user = {
                id: user.police_id,
                name: user.name,
                email: user.email
            };

            // Authentication successful
            return res.status(200).json({ message: 'Login successful', redirect: '/CrimeMonitoring.html' });
        });
    });
});



app.get('/get-user', (req, res) => {
    if (req.session.user) {
        return res.status(200).json({ user: req.session.user });
    } else {
        return res.status(401).json({ message: 'Not logged in' });
    }
});


app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.status(200).json({ message: 'Logged out successfully' });
    });
});


const otpStorage = new Map(); // Temporarily store OTPs (Use a database in production)

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'brightonanthonybusiness@gmail.com',
        pass: process.env.pass
    }
});

// Route to send OTP to email
app.post('/send-reset-otp',async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    // Check if email is already registered
    const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(checkEmailQuery, [email], async (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ success: false, message: 'Server error. Try again later.' });
        }

        if (results.length == 0) {
            return res.status(400).json({ success: false, message: 'This email is not registered.' });
        }

        // Extract domain from email (e.g., 'gmail.com' from 'test@gmail.com')
        const domain = email.split('@')[1];

        try {
            const mxRecords = await resolveMx(domain);

            if (!mxRecords || mxRecords.length === 0) {
                return res.status(400).json({ success: false, message: 'Invalid email address. Please enter a valid email.' });
            }
        } catch (error) {
            return res.status(400).json({ success: false, message: 'Invalid email domain. Please enter a valid email.' });
        }

    const otp = Math.floor(100000 + Math.random() * 900000); // Generate 6-digit OTP
    otpStorage.set(email, otp); // Store OTP temporarily

    // Send email with OTP
    const mailOptions = {
        from: 'brightonanthonybusiness@gmail.com',
        to: email,
        subject: 'Password Reset OTP',
        text: `Your OTP for resetting the password is: ${otp}`
    };

    transporter.sendMail(mailOptions, (error) => {
        if (error) {
            console.error('Error sending email:', error);
            return res.status(500).json({ success: false, message: 'Failed to send OTP.' });
        }
        res.json({ success: true, message: 'OTP sent to your email.' });
    });
    });
});

app.post('/reset-password', async (req, res) => {
    const { email, otp, password } = req.body;

    if (!otpStorage.has(email) || otpStorage.get(email) != otp) {
        return res.status(400).json({ success: false, message: 'Invalid OTP.' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update password in the database
    db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Error updating password.' });
        }

        otpStorage.delete(email); // Remove OTP after successful reset
        res.json({ success: true, message: 'Password reset successful. You can login now.' });
    });
});




app.post('/predict-crime', (req, res) => {
    const { crimeType, selectedDate, selectedTime } = req.body;

    console.log("Received request for crime prediction:", req.body);

    const pythonProcess = spawn("python", ["public/python/predict_crime.py", crimeType, selectedDate, selectedTime]);

    let outputData = "";
    let errorData = "";

    pythonProcess.stdout.on("data", (data) => {
        outputData += data.toString();
    });

    pythonProcess.stderr.on("data", (data) => {
        errorData += data.toString();
    });

    pythonProcess.on("close", (code) => {
        if (code !== 0) {
            console.error("Python script exited with error:", errorData);
            return res.status(500).json({ error: "Prediction error from Python script", details: errorData });
        }

        console.log("Raw Python script output:", outputData.trim());

        try {
            const crimePrediction = JSON.parse(outputData.trim());
            res.json(crimePrediction);
        } catch (parseError) {
            console.error("Error parsing Python output:", parseError);
            res.status(500).json({ error: "Invalid JSON format from Python script" });
        }
    });
});





// Fetch crime data for heatmap, crime_type, date
app.get('/api/crime-heatmap', (req, res) => {
    const sql = `SELECT latitude, longitude, COUNT(*) AS intensity FROM (
                SELECT latitude, longitude FROM policeregistration
                UNION ALL
                SELECT latitude, longitude FROM publicregistration where flag=1
                ) AS combined_data
                GROUP BY latitude, longitude;`;

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching heatmap data:', err);
            return res.status(500).json({ error: 'Database query failed' });
        }

        if (!results || results.length === 0) {
            console.warn('No crime data found.');
            return res.status(404).json({ error: 'No crime data found' });
        }

        // Convert results to GeoJSON format
        const geoJson = results.map(row => ({
            type: 'Feature',
            properties: { intensity: row.intensity },
            geometry: {
                type: 'Point',
                coordinates: [parseFloat(row.longitude), parseFloat(row.latitude)]
            }
        }));

        res.json({ type: 'FeatureCollection', features: geoJson });
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


const otpMap = new Map(); // Store OTPs temporarily (use a database for production)

// Endpoint to generate OTP
app.post('/generate-otp', (req, res) => {
    const { phoneNo } = req.body;

    if (!phoneNo) {
        return res.status(400).json({ success: false, message: 'Phone number is required.' });
    }

    // Generate a 6-digit random OTP
    const otp = Math.floor(100000 + Math.random() * 900000);

    // Save OTP with an expiration time (e.g., 5 minutes)
    otpMap.set(phoneNo, { otp, expiresAt: Date.now() + 5 * 60 * 1000 });

    // Send OTP via Twilio SMS
    twilioClient.messages.create({
        body: `Your OTP for crime reporting is: ${otp}`,
        from: TWILIO_PHONE_NUMBER,
        to: `+91${phoneNo}` // Change prefix based on country
    })
    .then(message => {
        console.log(`OTP for ${phoneNo}: ${otp}`);
        console.log(`OTP sent successfully! SID: ${message.sid}`);
        res.status(200).json({ success: true, message: 'OTP sent to your phone!' });
    })
    .catch(error => {
        console.error('Error sending OTP:', error);
        res.status(500).json({ success: false, message: 'Failed to send OTP' });
    });
});


// Endpoint to verify OTP
app.post('/verify-otp', (req, res) => {
    const { phoneNo, otp } = req.body;

    if (!phoneNo || !otp) {
        return res.status(400).json({ success: false, message: 'Phone number and OTP are required.' });
    }

    const storedOtp = otpMap.get(phoneNo);

    if (!storedOtp) {
        return res.status(400).json({ success: false, message: 'OTP expired or invalid.' });
    }

    if (storedOtp.otp.toString() === otp.toString() && Date.now() < storedOtp.expiresAt) {
        otpMap.delete(phoneNo); // Clear OTP after successful verification
        return res.status(200).json({ success: true, message: 'OTP verified successfully!' });
    } else {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
    }
});




//display the public registration
app.get('/fetch-public-registrations', (req, res) => {
    const fetchSql = `SELECT id, location, crime_type, latitude, longitude, video FROM publicregistration WHERE flag = 0`;
    
    db.query(fetchSql, (err, results) => {
        if (err) {
            console.error('Error fetching public registrations:', err);
            return res.status(500).json({ message: 'Failed to fetch records' });
        }
        res.json(results); // Send the fetched data to the client
    });
});


app.delete('/delete-record/:id', (req, res) => {
    const deleteSql = `DELETE FROM publicregistration WHERE id = ?`;
    const recordId = req.params.id;

    db.query(deleteSql, [recordId], (err, result) => {
        if (err) {
            console.error('Error deleting record:', err);
            return res.status(500).json({ success: false, message: 'Failed to delete record' });
        }
        res.json({ success: true, message: 'Record deleted successfully' });
    });
});


app.post('/approve-record/:id', (req, res) => {
    const editflag = `update publicregistration SET flag = 1 WHERE id = ?`;
    const recordId = req.params.id;

    db.query(editflag, [recordId], (err, result) => {
        if (err) {
            console.error('Error approving record:', err);
            return res.status(500).json({ success: false, message: 'Failed to approve record' });
        }
        res.json({ success: true, message: 'Record approved successfully' });
    
    });
});


// Route to serve video from the 'upload' folder
app.get('/video/:id', (req, res) => {
    const recordId = req.params.id;

    // Query to get the video filename from the database
    const fetchVideoSql = `SELECT video FROM publicregistration WHERE id = ?`;

    db.query(fetchVideoSql, [recordId], (err, results) => {
        if (err) {
            console.error('Error fetching video:', err);
            return res.status(500).send('Error fetching video');
        }

        if (results.length === 0) {
            return res.status(404).send('Video not found');
        }

        const videoFilename = results[0].video; // Assuming 'video' stores the filename (e.g., 'video.mp4')

        // Construct the full path to the video file in the 'upload' folder
        const videoPath = path.join(__dirname, 'uploads', videoFilename);

        // Check if the video file exists
        fs.access(videoPath, fs.constants.F_OK, (err) => {
            if (err) {
                console.error('Video file does not exist:', videoPath);
                return res.status(404).send('Video not found');
            }

            // Send the video file as a response
            res.sendFile(videoPath, (err) => {
                if (err) {
                    console.error('Error sending video file:', err);
                    return res.status(500).send('Error sending video');
                }
            });
        });
    });
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// fetching from db for marker
app.get('/locations', (req, res) => {
    const query = 'SELECT latitude, longitude, crime_type FROM publicregistration where flag=0'; // Example query
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching location data:', err);
            return res.status(500).json({ error: 'Database query error' });
        }
        res.json(results); // Send the lat/lng data to the frontend
    });
});



// Route to get count of crimes with flag=0
app.get('/crime-count', (req, res) => {
    const query = 'SELECT COUNT(*) AS crimeCount FROM publicregistration WHERE flag=0';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching data from MySQL:', err);
            res.status(500).send('Error fetching data');
        } else {
            const count = results[0].crimeCount;
            res.json({ crimeCount: count });
        }
    });
});




// fetching from db for marker
app.get('/hotspot_police', (req, res) => {
    const query = 'SELECT latitude, longitude, crime_type, date FROM policeregistration';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching location data:', err);
            return res.status(500).json({ error: 'Database query error' });
        }
        res.json(results); // Send the lat/lng data to the frontend
    });
});


app.get('/hotspot_public', (req, res) => {
    const query = 'SELECT latitude, longitude, crime_type, date FROM publicregistration where flag=1';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching location data:', err);
            return res.status(500).json({ error: 'Database query error' });
        }
        res.json(results); // Send the lat/lng data to the frontend
    });
});


app.use('/uploads/photos', express.static(path.join(__dirname, 'uploads/photos')));
// API to fetch criminal data
app.get('/api/criminals', (req, res) => {
    const criminalName = req.query.name || ''; // Get criminal name from query
    const query = criminalName
        ? `SELECT criminal_photo, criminal_name, latitude, longitude, crime_type, crime_dec, date FROM policeregistration WHERE criminal_name LIKE ?`
        : `SELECT criminal_photo, criminal_name, latitude, longitude, crime_type, crime_dec, date FROM policeregistration`;

    db.query(query, [`%${criminalName}%`], (err, results) => {
        if (err) {
            console.error('Error fetching data:', err);
            res.status(500).json({ error: 'Failed to fetch data' });
        } else {
            res.json(results);
        }
    });
});


// Start the server and bind it to 0.0.0.0 to allow access from other devices on the network
app.listen(3000, '0.0.0.0', () => {
    console.log('Server running at http://0.0.0.0:3000/');
});


//      http://localhost:3000/
//      node server.js
//      C:\Users\princy\Desktop\ngrok-v3-stable-windows-amd64\ngrok.exe http 3000
//      conda activate base
