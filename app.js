const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');

const app = express();

const port = 3000;
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'asel3127',
  port: 5433,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

async function authenticateUser(req, res, next) {
  const { username, password } = req.body;
  console.log('Received login data:', { username, password });

  const query = 'SELECT * FROM users WHERE username = $1';
  const values = [username];

  try {
    const result = await pool.query(query, values);
    console.log('Result from the database:', result.rows);

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      req.user = user;
      next();
    } else {
      return res.status(401).send('Invalid password');
    }
  } catch (error) {
    console.error('Error login user:', error);
    res.status(500).send('Error login user');
  }
}


function checkUserRole(req, res, next) {
  if (!req.user) {
    return res.redirect('/login.html');
  }

  const userRole = req.user.role;
  const requestedPage = path.basename(req.path);

  if (userRole === 'user' && requestedPage === 'user.html') {
    next();
  } else if (userRole === 'admin' && (requestedPage === 'admin.html' || requestedPage === 'moderator.html')) {
    next();
  } else if (userRole === 'moderator' && requestedPage === 'moderator.html') {
    next();
  } else {
    res.redirect('/unauthorized.html');
  }
}


app.post('/api/auth/signin', authenticateUser, (req, res) => {
  console.log('Authentication successful');
  const role = req.user.role;
  if (role === 'user') {
    console.log('Redirecting to /user.html');
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Location', '/user.html');
    res.status(302).end();
  } else if (role === 'admin') {
    console.log('Redirecting to /admin.html');
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Location', '/admin.html');
    res.status(302).end();
  } else if (role === 'moderator') {
    console.log('Redirecting to /moderator.html');
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Location', '/moderator.html');
    res.status(302).end();
  }
});


app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query =
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *';
    const values = [username, email, hashedPassword, role];

    const result = await pool.query(query, values);

    req.user = result.rows[0];
    res.status(200).json({ message: 'User added successfully', user: req.user });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to add user' });
  }
});


app.post('/api/admin/adduser', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query =
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *';
    const values = [username, email, hashedPassword, role];

    const result = await pool.query(query, values);

    res.status(200).json({ message: 'User added successfully', user: result.rows[0] });
  } catch (error) {
    console.error('Add user error:', error);
    res.status(500).json({ error: 'Failed to add user' });
  }
});

app.delete('/api/admin/deleteuser', async (req, res) => {
  try {
    const { userIdToDelete } = req.body;

    const query = 'DELETE FROM users WHERE id = $1 RETURNING *';
    const values = [userIdToDelete];

    const result = await pool.query(query, values);

    res.status(200).json({ message: 'User deleted successfully', user: result.rows[0] });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/user.html', checkUserRole, (req, res) => {
  res.sendFile(path.join(__dirname, 'user.html'));
});

app.get('/admin.html', checkUserRole, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/moderator.html', checkUserRole, (req, res) => {
  res.sendFile(path.join(__dirname, 'moderator.html'));
});


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});