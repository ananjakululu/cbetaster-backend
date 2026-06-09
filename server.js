require('dotenv').config({ override: true });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_change_this'; 
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// --- SECURITY CONFIGURATION ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
});

const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts. Please try again later.' }
});

// --- Middleware Setup ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://*", "http://*"],
            connectSrc: ["'self'", "https://api.openai.com", "https://cdnjs.cloudflare.com"] 
        },
    },
}));
app.use(morgan('dev'));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Database Helpers (ROBUST) ---
async function initializeDefaultDB() {
    console.log('⚙️ Initializing new database...');
    const defaultPassword = 'password'; 
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);
    
    const initialData = { 
        students: [], exams: [], finance: [], staff: [], inventory: [], 
        trades: [], settings: { schoolName: "TVET Institute" },
        users: [{ email: 'admin@tvet.ac.ke', passwordHash: hashedPassword, role: 'admin' }]
    };
    await saveDB(initialData);
    return initialData;
}

async function loadDB() {
    try {
        const data = await fs.readFile(DB_FILE, 'utf8');
        
        // FIX: Handle empty file case
        if (!data || data.trim() === '') {
            return await initializeDefaultDB();
        }

        return JSON.parse(data);
    } catch (err) {
        // If file doesn't exist or JSON is invalid, regenerate
        if (err.code === 'ENOENT' || err instanceof SyntaxError) {
            return await initializeDefaultDB();
        }
        throw err;
    }
}

async function saveDB(data) {
    await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

// --- ROUTES ---

app.post('/api/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    const db = await loadDB();
    const user = db.users.find(u => u.email === email);

    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const token = jwt.sign({ email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token, user: { email: user.email, role: user.role } });
});

// Protected Routes
app.get('/api/students', authenticateToken, async (req, res) => {
    try {
        const db = await loadDB();
        res.json(db.students || []);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load students' });
    }
});

app.post('/api/students', authenticateToken, async (req, res) => {
    try {
        const db = await loadDB();
        const newStudent = { id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5), ...req.body };
        db.students.push(newStudent);
        await saveDB(db);
        res.status(201).json(newStudent);
    } catch (err) {
        res.status(500).json({ error: 'Failed to save student' });
    }
});

app.put('/api/students/:id', authenticateToken, async (req, res) => {
    try {
        const db = await loadDB();
        const index = db.students.findIndex(s => s.id === req.params.id);
        if (index === -1) return res.status(404).json({ error: 'Student not found' });
        db.students[index] = { ...db.students[index], ...req.body };
        await saveDB(db);
        res.json(db.students[index]);
    } catch (err) {
        res.status(500).json({ error: 'Failed to update student' });
    }
});

app.delete('/api/students/:id', authenticateToken, async (req, res) => {
    try {
        const db = await loadDB();
        db.students = db.students.filter(s => s.id !== req.params.id);
        db.exams = db.exams.filter(e => e.studentId !== req.params.id);
        db.finance = db.finance.filter(f => f.studentId !== req.params.id);
        await saveDB(db);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete student' });
    }
});

app.post('/api/finance', authenticateToken, async (req, res) => {
    try {
        const db = await loadDB();
        const transaction = { id: Date.now().toString(36), date: new Date().toISOString(), ...req.body };
        db.finance.push(transaction);
        if (req.body.studentId) {
            const student = db.students.find(s => s.id === req.body.studentId);
            if (student) student.fees = Math.max(0, student.fees - req.body.amount);
        }
        await saveDB(db);
        res.status(201).json(transaction);
    } catch (err) {
        res.status(500).json({ error: 'Failed to record transaction' });
    }
});

// --- THE BAD FETCH BLOCK HAS BEEN REMOVED FROM HERE ---

app.post('/api/db', authenticateToken, async (req, res) => {
    try {
        await saveDB(req.body);
        res.json({ success: true, message: 'Database saved' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to save database' });
    }
});

app.post('/api/ai/chat', authenticateToken, async (req, res) => {
    const { query, context, focus } = req.body;
    if (!OPENAI_API_KEY) return res.status(500).json({ error: 'Server configuration error: Missing API Key.' });

    const systemPrompt = `You are a helpful assistant for ${context.schoolName}. Stats: ${context.totalStudents} students.`;
    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
            body: JSON.stringify({ model: 'gpt-3.5-turbo', messages: [ { role: 'system', content: systemPrompt }, { role: 'user', content: query } ], temperature: 0.7 })
        });
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json({ error: data.error.message });
        res.json({ reply: data.choices[0].message.content });
    } catch (error) {
        res.status(500).json({ error: 'Failed to connect to AI services.' });
    }
});

// --- Start Server ---
// We added '0.0.0.0' here to allow access from your phone
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 TVET Manager running at http://localhost:${PORT}`);
    console.log(`🌐 Network Access: http://192.168.43.200:${PORT}`); 
    console.log(`👉 Login: admin@tvet.ac.ke / password`);
    if (!OPENAI_API_KEY) console.warn('⚠️ WARNING: AI Features Disabled.');
});