const express = require('express');
const cors = require('cors');
const requestIp = require('request-ip');
require('dotenv').config();
const logger = require('./utils/logger');


const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestIp.mw());

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});