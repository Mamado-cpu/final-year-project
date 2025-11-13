const mongoose = require('mongoose');

const locationSchema = new mongoose.Schema({
    collector: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    location: {
        type: {
            type: String,
            enum: ['Point'],
            required: true,
        },
        coordinates: {
            type: [Number],
            required: true,
        },
    },
    lastUpdated: {
        type: Date,
        default: Date.now,
    },
    isOnline: {
        type: Boolean,
        default: true,
    },
    speed: {
        type: Number,
        default: 0,
    },
    heading: {
        type: Number,
        default: 0,
    },
    accuracy: {
        type: Number,
    },
    address: {
        type: String,
    },
});

locationSchema.index({ location: '2dsphere' });

module.exports = mongoose.model('Location', locationSchema);