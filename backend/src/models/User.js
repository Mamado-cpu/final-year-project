const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    // NOTE: firebaseUid removed — using local JWT / MongoDB for authentication
    fullName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    // Local password (hashed). Optional if using external auth providers.
    password: {
        type: String,
    },
    phone: {
        type: String,
        required: false,
    },
    locationAddress: String,
    locationLat: Number,
    locationLng: Number,
    roles: [{
        type: String,
        enum: ['resident', 'collector', 'admin'],
        default: ['resident']
    }],
    // isApproved removed - users can access immediately after registration
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    }
});

userSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('User', userSchema);