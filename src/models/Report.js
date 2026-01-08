const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    collectorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Collector',
    },
    locationAddress: {
        type: String,
        required: true,
    },
    locationLat: {
        type: Number,
        required: true,
    },
    locationLng: {
        type: Number,
        required: true,
    },
    photoUrl: String,
    description: {
        type: String,
        required: true,
    },
    status: {
        type: String,
        enum: ['pending', 'assigned', 'in_progress', 'cleared', 'rejected'],
        default: 'pending',
    },
    reportedAt: {
        type: Date,
        default: Date.now,
    },
    assignedAt: Date,
    startedAt: Date,
    clearedAt: Date,
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    }
});

reportSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('Report', reportSchema);