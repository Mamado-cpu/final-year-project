const mongoose = require('mongoose');

const collectorSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true,
    unique: true 
  },
  // Denormalized profile fields stored on Collector for quick access
  fullName: { type: String },
  username: { type: String },
  email: { type: String },
  phone: { type: String },
  vehicleNumber: { type: String },
  vehicleType: { type: String },
  isAvailable: { type: Boolean, default: true },
  currentLat: { type: Number },
  currentLng: { type: Number },
  lastLocationUpdate: { type: Date },
  currentRoute: {
    type: {
      type: String,
      enum: ['LineString'],
    },
    coordinates: [[Number]],
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Add geospatial index for location queries
collectorSchema.index({ currentRoute: '2dsphere' });

// Update timestamps before saving
collectorSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Method to update real-time location
collectorSchema.methods.updateLocation = async function(latitude, longitude) {
  this.currentLat = latitude;
  this.currentLng = longitude;
  this.lastLocationUpdate = new Date();
  
  // Add point to current route if it exists
  if (this.currentRoute && this.currentRoute.coordinates) {
    this.currentRoute.coordinates.push([longitude, latitude]);
    
    // Keep only last 100 points to avoid excessive data
    if (this.currentRoute.coordinates.length > 100) {
      this.currentRoute.coordinates = this.currentRoute.coordinates.slice(-100);
    }
  } else {
    this.currentRoute = {
      type: 'LineString',
      coordinates: [[longitude, latitude]]
    };
  }
  
  return this.save();
};

module.exports = mongoose.model('Collector', collectorSchema);