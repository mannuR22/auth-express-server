const express = require('express');
const bodyParser = require('body-parser');
const winston = require('winston');

const app = express();
const port = process.env.PORT || 3000;
const logger = require('./utils/logger')
const db = require('./utils/mongoose')

db();
require('dotenv').config()

app.use(bodyParser.json());

// Routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

// Middleware
const middleware = require('./middleware/user');

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/api/users', middleware, userRoutes);

// Hello World Route
app.get('/', (req, res) => {
  logger.info('Hello World route accessed.');
  res.send('Hello, World!');
});

// Start the server
app.listen(port, () => {
  logger.info(`Server is running on port ${port}`);
});
