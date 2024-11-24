const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(express.json());

// Database setup
const MONGO_URI = process.env.MONGO_URI || 4040 ; 
mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Error connecting to MongoDB:', err.message));

const jwtSecret = crypto.randomBytes(64).toString('hex');
const PORT = process.env.PORT || 4040;

// Define MongoDB Schemas and Models
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true }
});

const TodoSchema = new mongoose.Schema({
    task: { type: String, required: true },
    status: { type: String, required: true },
    userId: { type: String, required: true}
});

const User = mongoose.model('User', UserSchema);
const Todo = mongoose.model('Todo', TodoSchema);

// CORS setup
app.use(
    cors({
        origin: 'http://localhost:3000',
    })
);

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Endpoints

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id, username: user.username }, jwtSecret, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful', token });
    } catch (err) {
        console.error('Error logging in user:', err.message);
        res.status(500).json({ message: 'Error logging in user' });
    }
});

// User registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error registering user:', err.message);
        res.status(500).json({ message: 'Error registering user' });
    }
});

// Get user details
app.get('/userDetails', async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json({ result: users });
    } catch (err) {
        console.error('Error fetching user details:', err.message);
        res.status(500).json({ message: 'Error fetching user details' });
    }
});

// Add a new todo
app.post('/todoPost/:userId',authenticateToken, async (req, res) => {
    const { task, status } = req.body;
    const userId = req.params.userId;

    try {
        const newTodo = new Todo({ task, status, userId });
        await newTodo.save();
        res.status(200).json({ message: 'New todo added successfully' });
    } catch (err) {
        console.error('Error adding todo:', err.message);
        res.status(500).json({ message: 'Error adding todo' });
    }
});

// Get user's todo list
app.get('/todoList/:userId',authenticateToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        const todos = await Todo.find({ userId });
        res.status(200).json({ todos });
    } catch (err) {
        console.error('Error fetching todos:', err.message);
        res.status(500).json({ message: 'Error fetching todos' });
    }
});

// Update a todo
app.put('/updateTodo/:id',authenticateToken, async (req, res) => {
    const id = req.params.id;
    const { task, status } = req.body;

    try {
        const updatedTodo = await Todo.findByIdAndUpdate(id, { task, status }, { new: true });
        res.status(200).json({ message: 'Todo updated successfully', updatedTodo });
    } catch (err) {
        console.error('Error updating todo:', err.message);
        res.status(500).json({ message: 'Failed to update todo' });
    }
});

// Delete a todo
app.delete('/deleteTodo/:id', authenticateToken, async (req, res) => {
    const id = req.params.id;

    try {
        await Todo.findByIdAndDelete(id);
        res.status(200).json({ message: 'Todo deleted successfully' });
    } catch (err) {
        console.error('Error deleting todo:', err.message);
        res.status(500).json({ message: 'Failed to delete todo' });
    }
});

// Delete all users
app.delete('/deleteUsers', async (req, res) => {
    try {
        await User.deleteMany();
        res.status(200).json({ message: 'Successfully deleted all users' });
    } catch (err) {
        console.error('Error deleting users:', err.message);
        res.status(500).json({ message: 'Failed to delete users' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
