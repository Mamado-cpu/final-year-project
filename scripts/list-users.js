require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../src/models/User');

async function listUsers() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    const users = await User.find({}).select('username email roles createdAt');
    console.log('Users:');
    users.forEach(u => console.log(u));
  } catch (e) {
    console.error('Error listing users:', e.message || e);
  } finally {
    await mongoose.connection.close();
    process.exit(0);
  }
}

listUsers();
