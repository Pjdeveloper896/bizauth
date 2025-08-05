const express = require('express');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

const PORT = 4000;
const SECRET = "supersecretkey123";
const USERS_FILE = './users.json';
const FRONTEND_URL = "https://biz-tracker-vert.vercel.app";

// Create users file if it doesn't exist
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');

function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// === Serve Login/Signup UI ===
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Login | BizTracker</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background: #f4f6f8;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
        }
        .container {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 0 15px rgba(0,0,0,0.1);
          width: 100%;
          max-width: 400px;
        }
        h2 {
          text-align: center;
          margin-bottom: 20px;
        }
        input {
          width: 100%;
          padding: 10px;
          margin: 8px 0;
          border: 1px solid #ccc;
          border-radius: 4px;
        }
        button {
          width: 100%;
          padding: 10px;
          background: #007BFF;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        button:hover {
          background: #0056b3;
        }
        .switch {
          text-align: center;
          margin-top: 10px;
        }
        .switch a {
          color: #007BFF;
          text-decoration: none;
        }
        .message {
          text-align: center;
          color: green;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h2 id="form-title">Login</h2>
        <form id="auth-form" method="POST" action="/login">
          <div id="name-field" style="display: none;">
            <input type="text" name="name" placeholder="Full Name" />
          </div>
          <input type="email" name="email" placeholder="Email" required />
          <input type="password" name="password" placeholder="Password" required />
          <button type="submit">Login</button>
        </form>
        <div class="switch">
          <span id="switch-text">Don't have an account? <a href="#" onclick="toggleForm()">Signup</a></span>
        </div>
        <div class="message" id="msg"></div>
      </div>

      <script>
        function toggleForm() {
          const form = document.getElementById('auth-form');
          const nameField = document.getElementById('name-field');
          const title = document.getElementById('form-title');
          const switchText = document.getElementById('switch-text');

          if (form.action.includes('/login')) {
            form.action = '/signup';
            nameField.style.display = 'block';
            title.innerText = 'Signup';
            switchText.innerHTML = 'Already have an account? <a href="#" onclick="toggleForm()">Login</a>';
          } else {
            form.action = '/login';
            nameField.style.display = 'none';
            title.innerText = 'Login';
            switchText.innerHTML = 'Don\\'t have an account? <a href="#" onclick="toggleForm()">Signup</a>';
          }
        }

        const params = new URLSearchParams(window.location.search);
        if (params.has('token')) {
          localStorage.setItem('biztoken', params.get('token'));
          window.location.href = '${FRONTEND_URL}?token=' + params.get('token');
        }
      </script>
    </body>
    </html>
  `);
});

// === Signup Route ===
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const users = loadUsers();

  const exists = users.find(u => u.email === email);
  if (exists) return res.status(400).json({ error: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now(), name, email, password: hashed };
  users.push(newUser);
  saveUsers(users);

  const token = jwt.sign({ id: newUser.id, name: newUser.name }, SECRET, { expiresIn: '1h' });
  res.redirect(`${FRONTEND_URL}?token=${token}`);
});

// === Login Route ===
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();

  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: 'Wrong password' });

  const token = jwt.sign({ id: user.id, name: user.name }, SECRET, { expiresIn: '1h' });
  res.redirect(`${FRONTEND_URL}?token=${token}`);
});

// === Protected Route ===
app.get('/protected', (req, res) => {
  const bearer = req.headers['authorization'];
  if (!bearer) return res.status(403).json({ error: 'No token provided' });

  const token = bearer.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    res.json({ message: 'Access granted', user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
