const mongoose = require('mongoose');
require('dotenv').config();

const User = require('../src/models/User');
const Collector = require('../src/models/Collector');

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('MONGODB_URI not set in environment');
    process.exit(1);
  }

  await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');

  try {
    const collectors = await Collector.find({}).select('userId');
    console.log(`Found ${collectors.length} collector profiles`);

    let updated = 0;
    for (const c of collectors) {
      const userId = c.userId;
      if (!userId) continue;
      const user = await User.findById(userId);
      if (!user) continue;
      if (!user.roles || !user.roles.includes('collector')) {
        user.roles = Array.from(new Set([...(user.roles || []), 'collector']));
        await user.save();
        updated += 1;
        console.log(`Updated user ${user._id} to include 'collector' role`);
      }
    }

    console.log(`Done. Updated ${updated} users.`);
  } catch (err) {
    console.error('Error during sync:', err && err.stack ? err.stack : err);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

main();
