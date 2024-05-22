const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false })); 
app.use(bodyParser.json()); 
app.use(express.json());
const port = 2000; // Adjust port number as needed

// Database credentials
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'attendance_management_system'
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Unauthorized access: Token missing');
  jwt.verify(token.replace('Bearer ', ''), 'natalie', (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).send('Unauthorized access: Invalid or expired token');
    }
    req.userId = decoded.id;
    next();
  });
};

// Get all data from a roles table
app.get('/students',verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM students');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving students');
  }
});

// Select Single role
app.get('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.query('SELECT * FROM students WHERE s_id = ?', [id]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error showing students');
  }
});

// Insert data into roles table
app.post('/students', verifyToken, async (req, res) => {
  const { ins_id, name, reg_no, created_at, updated_at, created_by, updated_by } = req.body; // Destructure data from request body
  if (!ins_id || !name || !reg_no || !created_at || !updated_at || !created_by || !updated_by ) {
    return res.status(400).send('Please provide all required fields ');
  }
  try {
    const [result] = await pool.query('INSERT INTO students SET ?', { ins_id, name, reg_no,  created_at, updated_at, created_by, updated_by});
    res.json({ message: `student inserted successfully with ID: ${result.insertId}` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error inserting student');
  }
});

// Update role
app.put('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const { ins_id, name, reg_no, created_at, updated_at, created_by, updated_by } = req.body; // Destructure data from request body
  if (!ins_id || !name || !reg_no || !created_at || !updated_at || !created_by || !updated_by ) {
    return res.status(400).send('Please provide all required fields ');
  }
  try {
    const [result] = await pool.query('UPDATE students SET ins_id=?, name=?, reg_no=?, created_at=?, updated_at=?, created_by=?, updated_by=? WHERE s_id = ?', [ins_id,  name, reg_no, created_at, updated_at, created_by, updated_by, id]);
      // Use ID from request params
    const [rows] = await pool.query('SELECT * FROM students WHERE s_id = ?', [id]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating student');
  }
});

// PATCH route to partially update reg_no and name of an existing student
app.patch('/students/:id', verifyToken, async (req, res) => {
  const studentId = req.params.id;
  const { reg_no, name } = req.body; // Destructure reg_no and name from request body
  if (!reg_no && !name) {
      return res.status(400).send('Please provide at least one field to update ');
  }
  try {
      let updateData = {};
      if (name) updateData.name = name;
      if (reg_no) updateData.reg_no = reg_no;
      const [result] = await pool.query('UPDATE students SET ? WHERE s_id=?', [updateData, studentId]);
      if (result.affectedRows === 0) {
          res.status(404).json({ message: 'Student not found' });
      } else {
          res.status(200).json({ message: 'Student updated successfully' });
      }
  } catch (err) {
      console.error(err);
      res.status(500).send('Error updating student');
  }
});


// Delete role by ID
app.delete('/students/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM students WHERE s_id = ?', [id]);
    res.json({ message: `student with ID ${id} deleted successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting student');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { user_name,Password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE user_name = ?', [user_name]);
    if (!users.length) {
      return res.status(404).send('User not found');
    }

    const user = users[0];
    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(Password, user.Password);
    if (!passwordMatch) {
      return res.status(401).send('Invalid password');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id }, 'natalie', { expiresIn: '1h' });

    // Send the token as response
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
