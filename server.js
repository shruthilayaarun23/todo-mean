const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config(); // Load environment variables

const app = express();
const port = process.env.PORT || 3000; // Use environment variable for port

// Middleware
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files from the 'public' directory

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('MongoDB connected successfully');
}).catch((err) => {
    console.error('MongoDB connection error:', err);
});

// User schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});
const User = mongoose.model('User', userSchema);

// ToDo schema
const todoSchema = new mongoose.Schema({
    task: String,
    userId: String, // Associate todo with user
    createdAt: { type: Date, default: Date.now } // Store creation time
});
const Todo = mongoose.model('Todo', todoSchema);

// Middleware for authentication
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token) {
        jwt.verify(token, 'your_jwt_secret', (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// Routes
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if the user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(400).send('User already exists.'); // Handle user already exists
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.sendStatus(201); // User created successfully
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).send('Internal Server Error'); // Handle unexpected errors
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id }, 'your_jwt_secret');
        res.json({ token });
    } else {
        res.sendStatus(401);
    }
});

// ToDo routes
app.get('/api/todos', authenticateJWT, async (req, res) => {
    const todos = await Todo.find({ userId: req.user.id }); // Get todos for the authenticated user
    res.json(todos);
});

app.post('/api/todos', authenticateJWT, async (req, res) => {
    const todo = new Todo({ task: req.body.task, userId: req.user.id });
    await todo.save();
    res.sendStatus(201);
});

app.put('/api/todos/:id', authenticateJWT, async (req, res) => {
    await Todo.findByIdAndUpdate(req.params.id, { task: req.body.task });
    res.sendStatus(204);
});

app.delete('/api/todos/:id', authenticateJWT, async (req, res) => {
    await Todo.findByIdAndDelete(req.params.id);
    res.sendStatus(204);
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
