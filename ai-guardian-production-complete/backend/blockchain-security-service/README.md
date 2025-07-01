# Blockchain Security Service

## Purpose

The Blockchain Security Service is a specialized service for analyzing the security of blockchain and Web3 assets. It can analyze smart contracts, identify common vulnerabilities like re-entrancy, and monitor on-chain activity.

## API Endpoints

### Core Analysis (`/api/blockchain/`)
- `POST /api/blockchain/analyze-smart-contract`: Performs a deep analysis of Solidity or Vyper smart contract code.
- `POST /api/blockchain/analyze-defi-protocol`: Analyzes a DeFi protocol for security risks.
- `POST /api/blockchain/analyze-liquidity-pool`: Assesses a liquidity pool for risks like rug pulls.
- `POST /api/blockchain/analyze-flash-loan`: Analyzes a specific flash loan transaction for attack vectors.

### Monitoring & Detection (`/api/blockchain/`)
- `POST /api/blockchain/monitor-transactions`: Monitors a set of addresses for suspicious activity.
- `POST /api/blockchain/detect-rug-pull`: Analyzes a token for indicators of a rug pull.

### Reporting & Compliance (`/api/blockchain/`)
- `POST /api/blockchain/audit-report`: Generates a formal security audit report for a smart contract.
- `POST /api/blockchain/compliance-check`: Checks a contract against known compliance standards.
- `POST /api/blockchain/gas-optimization`: Suggests gas optimization improvements.

### Health Check
- `GET /health`: Returns the health status of the service. 