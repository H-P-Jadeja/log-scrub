'use strict';

// npm install express @bladegg/log-scrub
const express = require('express');
const { expressMiddleware } = require('../src'); // or require('@bladegg/log-scrub')

const app = express();
app.use(express.json());
app.use(expressMiddleware({ keys: ['otp'] }));

app.post('/login', (req, res) => {
  console.log('incoming request:', req.scrubbed()); // safe to log
  res.json({ ok: true });
});

app.listen(3000, () => console.log('Listening on :3000'));
