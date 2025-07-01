# IoT and Mobile Security Service

## Purpose

This service specializes in the security analysis of Internet of Things (IoT) devices and mobile applications (Android & iOS). It can analyze firmware, device network traffic, and application packages for vulnerabilities.

## API Endpoints

### IoT Analysis (`/api/iot/`)
- `POST /api/iot/scan-device`: Scans a network-connected IoT device.
- `POST /api/iot/analyze-firmware`: Analyzes a provided firmware binary.
- `POST /api/iot/device-discovery`: Discovers IoT devices on a given network segment.
- `POST /api/iot/vulnerability-assessment`: Performs a vulnerability assessment on a known device type.
- `POST /api/iot/security-audit`: Runs a full security audit against an IoT device.

### Mobile Analysis (`/api/mobile/`)
- `POST /api/mobile/analyze-android-app`: Analyzes an Android APK file.
- `POST /api/mobile/analyze-ios-app`: Analyzes an iOS IPA file.
- `POST /api/mobile/cross-platform-analysis`: Compares the security posture of an app across platforms.
- `POST /api/mobile/privacy-analysis`: Focuses on privacy-related issues in a mobile app.
- `POST /api/mobile/malware-detection`: Scans a mobile app for known malware signatures.
- `POST /api/mobile/app-store-analysis`: Analyzes an application directly from an app store.

### Network Analysis (`/api/network/`)
- `POST /api/network/analyze-iot-network`: Scans an IoT network for insecure protocols and configurations.
- `POST /api/network/analyze-protocol`: Analyzes a specific communication protocol (e.g., MQTT, CoAP).

### Health Check
- `GET /health`: Returns the health status of the service. 