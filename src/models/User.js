const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    // NOTE: firebaseUid removed — using local JWT / MongoDB for authentication
    fullName: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
        unique: true,
    },
    email: {
        type: String,
        required: false,
        unique: false,
    },
    // Local password (hashed). Optional if using external auth providers.
    password: {
        type: String,
    },
    phone: {
        type: String,
        required: false,
    },
    // Two-factor authentication fields
    twoFactorEnabled: {
        type: Boolean,
        default: false,
    },
    twoFactorMethod: {
        type: String,
        enum: ['email', 'phone'],
    },
    twoFactorCode: String,
    twoFactorExpires: Date,
    twoFactorLastSent: Date,
    locationAddress: String,
    locationLat: Number,
    locationLng: Number,
    roles: {
        type: [String],
        enum: ['resident', 'collector', 'admin'],
        default: ['resident']
    },
    isApproved: {
        type: Boolean,
        default: true,
    },
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

// Sparse unique indexes so that absent emails/phones don't conflict
userSchema.index({ email: 1 }, { unique: true, sparse: true });
userSchema.index({ phone: 1 }, { unique: true, sparse: true });

userSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('User', userSchema);