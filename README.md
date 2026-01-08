# Waste Management System Backend API

This is the backend server for the Waste Management System.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create environment file:
```bash
cp .env.example .env
```

3. Update the `.env` file with your configuration values

4. Start the development server:
```bash
npm run dev
```

## API Endpoints

### Authentication
- POST /api/auth/register - Register a new user
- POST /api/auth/login - Login user

### Bookings
- POST /api/bookings - Create a new booking
- GET /api/bookings/resident - Get resident's bookings
- GET /api/bookings/collector - Get collector's bookings
- PUT /api/bookings/:id/status - Update booking status
- GET /api/bookings/all - Get all bookings (admin only)

### Reports
- POST /api/reports - Create a new illegal dumping report
- GET /api/reports/user - Get user's reports
- GET /api/reports/all - Get all reports (admin only)
- PUT /api/reports/:id/status - Update report status

### Locations
- POST /api/locations/update - Update collector location
- GET /api/locations/collector/:collectorId - Get collector location
- GET /api/locations/collectors - Get all active collectors
- GET /api/locations/nearest - Get nearest collectors

## Project Structure

```
src/
├── config/         # Configuration files
├── controllers/    # Request handlers
├── middlewares/    # Custom middleware functions
├── models/         # Database models
├── routes/         # Route definitions
└── utils/          # Utility functions
```