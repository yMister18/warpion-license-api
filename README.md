# Warpion License API

A comprehensive license management API for the Warpion platform.

## Features

- License validation and verification
- License activation and deactivation
- License expiration tracking
- Multi-tier license support
- RESTful API endpoints

## Installation

```bash
npm install warpion-license-api
```

## Quick Start

```javascript
const WarpionLicenseAPI = require('warpion-license-api');

const api = new WarpionLicenseAPI({
  apiKey: 'your-api-key'
});
```

## API Endpoints

### Validate License
```
POST /api/licenses/validate
```

### Activate License
```
POST /api/licenses/activate
```

### Deactivate License
```
POST /api/licenses/deactivate
```

### Get License Status
```
GET /api/licenses/:licenseId
```

## Configuration

Create a `.env` file in the root directory:

```env
API_PORT=3000
API_KEY=your-secret-key
DATABASE_URL=your-database-url
```

## Testing

```bash
npm test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please contact: support@warpion.com