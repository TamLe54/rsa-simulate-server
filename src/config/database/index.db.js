const mongoose = require('mongoose');
require('dotenv').config();

async function connect() {
  try {
    mongoose.set('strictQuery', true);
    await mongoose.connect(process.env.DB_URL, {});
    console.log('Connected to database');
  } catch (error) {
    console.log('Connecting failed!', error);
  }
}

module.exports = { connect };
