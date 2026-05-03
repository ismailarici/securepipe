const express = require('express');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// Hardcoded secrets — intentional for demo
const API_KEY = 'secret_api_key_12345abcdef';
const DB_PASSWORD = 'admin123';

// OS command injection — shell=true with unsanitised input
app.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.json({ result: stdout });
  });
});

// Reflected XSS — user input rendered raw
app.get('/hello', (req, res) => {
  const name = req.query.name || 'World';
  res.send(`<h1>Hello ${name}</h1>`);
});

// Prototype pollution via Object.assign
app.post('/merge', (req, res) => {
  const target = {};
  Object.assign(target, req.body);
  res.json(target);
});

app.listen(3000, () => console.log('Running on port 3000'));
