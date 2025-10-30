require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const verifyToken = require('./authMiddleware');

const app = express();
app.use(express.json());

// Dummy user data
const users = [
  { id: 1, username: 'vaidehi', passwordHash: bcrypt.hashSync('password123', 10), role: 'student' },
  { id: 2, username: 'mentor', passwordHash: bcrypt.hashSync('mentorPass', 10), role: 'admin' }
];

// Login route — generates JWT
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: 'Invalid username or password' });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ message: 'Invalid username or password' });

  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );

  res.json({ message: 'Login successful', token });
});

// Public route
app.get('/api/public', (req, res) => {
  res.json({ message: 'This is a public route accessible to everyone.' });
});

// Protected route
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}, you have accessed a protected route!` });
});

// Admin-only route
app.get('/api/admin', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied: Admins only.' });
  res.json({ message: 'Welcome, admin!' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
