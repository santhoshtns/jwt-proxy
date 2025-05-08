// server.js
import express from 'express';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import tokenHandler from './api/token.js';

dotenv.config();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.post('/api/token', (req, res) => tokenHandler(req, res));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Local server running at http://localhost:${PORT}/api/token`);
});
