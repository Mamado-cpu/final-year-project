const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
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
    // type of service: sewage disposal or garbage collection
    serviceType: {
        type: String,
        enum: ['sewage', 'garbage'],
        default: 'garbage'
    },
    // arbitrary details depending on serviceType
    serviceDetails: {
        type: mongoose.Schema.Types.Mixed,
    },
    status: {
        type: String,
        enum: ['pending', 'assigned', 'in_progress', 'completed', 'cancelled'],
        default: 'pending',
    },
    notes: String,
    requestedAt: {
        type: Date,
        default: Date.now,
    },
    assignedAt: Date,
    startedAt: Date,
    completedAt: Date,
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    }
});

bookingSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('Booking', bookingSchema);