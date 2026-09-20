require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors'); // Added CORS for frontend-backend communication
const path = require('path');

const app = express();
app.use(cors()); // Enable CORS
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 1. Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas successfully'))
    .catch(err => console.error('Database connection error:', err));

// 2. Define Database Schemas & Models
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    // Changed roles to match frontend: 'visitor' (Student), 'staff' (Admin)
    role: { type: String, enum: ['visitor', 'staff', 'master'], required: true },
    status: { type: String, default: 'Approved' } // Staff (Admins) start as 'Pending'
});
const User = mongoose.model('User', userSchema);

const ticketSchema = new mongoose.Schema({
    ticketId: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    name: { type: String, required: true },
    foodPreference: { type: String, required: true }, // Added Food Preference
    status: { type: String, enum: ['Pending', 'Approved', 'Used', 'Revoked'], default: 'Pending' },
    scannedBy: { type: String, default: null }, // To track who scanned
    scanTime: { type: String, default: null }   // To track when it was scanned
});
const Ticket = mongoose.model('Ticket', ticketSchema);

// 3. API Routes for Authentication & Tickets

// Register Student (Visitor) or Admin (Staff)
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already exists.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        // If role is 'staff' (Admin), set to Pending. If 'visitor' (Student), set to Approved.
        const initialStatus = (role === 'staff') ? 'Pending' : 'Approved';

        const newUser = new User({ name, email, password: hashedPassword, role, status: initialStatus });
        await newUser.save();
        res.status(201).json({ message: 'Registration successful!', status: initialStatus });
    } catch (err) {
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        
        // Master Admin Hardcoded Check for absolute security
        if (role === 'master' && email === process.env.MASTER_USER) {
            if (password === process.env.MASTER_PASS) {
                return res.json({ name: 'Master Admin', email: process.env.MASTER_USER, role: 'master' });
            } else {
                return res.status(401).json({ error: 'Invalid master credentials.' });
            }
        }

        const user = await User.findOne({ email, role });
        if (!user) return res.status(401).json({ error: 'Invalid email or role.' });

        if (user.status === 'Pending') return res.status(403).json({ error: 'Account awaiting Master Admin approval.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Incorrect password.' });

        res.json({ name: user.name, email: user.email, role: user.role });
    } catch (err) {
        res.status(500).json({ error: 'Server login error.' });
    }
});

// Fetch Tickets & Admins for Dashboards
app.get('/api/data', async (req, res) => {
    try {
        const tickets = await Ticket.find({});
        const users = await User.find({ role: 'staff' }, { password: 0 }); // Fetching admins (staff)
        res.json({ tickets, users });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch dashboard data.' });
    }
});

// Student Request Pass
app.post('/api/ticket/request', async (req, res) => {
    try {
        const { email, name, foodPreference } = req.body;
        const existingTicket = await Ticket.findOne({ email });
        if (existingTicket) return res.status(400).json({ error: 'Pass already requested or issued.' });

        const newTicket = new Ticket({
            ticketId: 'MMCC26-' + Math.floor(Math.random() * 90000 + 10000), // Changed to MMCC26-
            email,
            name,
            foodPreference, // Saving food preference
            status: 'Pending'
        });
        await newTicket.save();
        res.json({ message: 'Pass requested successfully', ticket: newTicket });
    } catch (err) {
        res.status(500).json({ error: 'Failed to request ticket.' });
    }
});

// Admin Approve or Remove Pass
app.post('/api/ticket/action', async (req, res) => {
    try {
        const { ticketId, action } = req.body; // action can be 'Approved' or 'Revoked'
        const ticket = await Ticket.findOne({ ticketId });
        if (!ticket) return res.status(404).json({ error: 'Ticket not found.' });

        ticket.status = action;
        await ticket.save();
        res.json({ message: `Ticket status updated to ${action}` });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update ticket.' });
    }
});

// Master Admin Approve Regular Admin (Staff)
app.post('/api/admin/approve', async (req, res) => {
    try {
        const { email } = req.body;
        await User.updateOne({ email }, { status: 'Approved' });
        res.json({ message: 'Admin approved successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to approve admin.' });
    }
});

// Door Scanner Verification
app.post('/api/ticket/scan', async (req, res) => {
    try {
        const { ticketId, scannedBy } = req.body; // Expecting who scanned it
        const ticket = await Ticket.findOne({ ticketId });

        if (!ticket || ticket.status === 'Pending' || ticket.status === 'Revoked') {
            return res.status(400).json({ success: false, message: 'Pass Not Found or Unauthorized' });
        }
        if (ticket.status === 'Used') {
            return res.status(400).json({ success: false, message: `Pass Already Used! (${ticket.name})` });
        }

        ticket.status = 'Used';
        ticket.scannedBy = scannedBy || 'System'; // Track the admin
        ticket.scanTime = new Date().toLocaleString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
        
        await ticket.save();
        res.json({ success: true, message: `Entry granted for: ${ticket.name}` });
    } catch (err) {
        res.status(500).json({ error: 'Scanner error.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
