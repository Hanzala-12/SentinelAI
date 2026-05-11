# SentinelAI

<div align="center">

**An Intelligent Phishing Investigation Platform**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-green)
![React](https://img.shields.io/badge/React-18%2B-61DAFB?logo=react)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

## Overview

SentinelAI is an enterprise-grade, intelligent phishing investigation platform focused on **threat reasoning** and evidence-driven analysis, not just model scoring. It combines advanced signal extraction, reputation correlation, explainable risk scoring, and structured threat reporting to provide transparent, actionable security intelligence.

### Key Philosophy

- **Evidence-First**: Reasoning chains grounded in verifiable security signals
- **Hybrid Intelligence**: Combines heuristic analysis with AI-assisted threat assessment
- **Transparent Reasoning**: Every finding includes ranked evidence and explanations
- **Production-Ready**: Modular, scalable architecture built for enterprise deployment

## Core Features

### 🔍 Signal Extraction Engine
- **URL Analysis**: Protocol validation, domain reputation, suspicious patterns
- **DOM Signals**: Behavioral indicators and page structure analysis
- **Content Analysis**: Scam language detection and text-based threat indicators
- **Reputation Intelligence**: Multi-source threat intelligence integration

### 🧠 Threat Reasoning Engine
- Weighted, configurable signal processing
- Explainable risk scoring with reasoning chains
- Structured threat report generation
- Configurable threat thresholds and policies

### 🔗 Threat Intelligence Integration
- **VirusTotal**: File and URL reputation
- **URLScan**: Advanced URL analysis and screenshots
- **AbuseIPDB**: IP reputation and abuse history

### 📊 Frontend Investigation Dashboard
- **Home**: Unified URL submission and real-time analysis
- **Threat Report**: Detailed reasoning chains, ranked evidence, remediation guidance
- **History**: Scan history with advanced filtering and search capabilities
- **Dashboard**: Security metrics and threat trends

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface                            │
│  (React Dashboard + Browser Extension)                       │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                         │
├─────────────────────────────────────────────────────────────┤
│  • Authentication & Authorization                           │
│  • Request Routing & Validation                             │
│  • Analysis Orchestration                                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 Intelligence Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│  Signal Extraction → Threat Reasoning → Reporting           │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│          External Threat Intelligence Providers             │
│  (VirusTotal, URLScan, AbuseIPDB)                          │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+
- Docker & Docker Compose (optional)
- Virtual environment management (venv/conda)

### Installation

1. **Clone and navigate to project**
   ```bash
   git clone <repository-url>
   cd is-project
   ```

2. **Set up Python environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your threat intelligence API keys
   ```

4. **Start backend**
   ```bash
   cd backend
   python main.py
   ```

5. **Start frontend**
   ```bash
   cd frontend/dashboard
   npm install
   npm run dev
   ```

### Docker Deployment
```bash
docker-compose up -d
```

## Project Structure

```
is-project/
├── backend/                          # FastAPI application
│   ├── ai_engine/                   # AI models and analysis
│   ├── api/                         # REST API endpoints
│   ├── database/                    # Database models & queries
│   ├── intelligence/                # Threat reasoning engine
│   ├── middleware/                  # Request processing
│   ├── models/                      # Domain models
│   ├── services/                    # Business logic
│   │   └── threat_intel/            # Provider integrations
│   └── utils/                       # Utilities
├── frontend/
│   ├── dashboard/                   # React web application
│   └── extension/                   # Browser extension
├── docker/                          # Docker configurations
├── docs/                            # Documentation
└── requirements.txt                 # Python dependencies
```

## API Documentation

The API is self-documenting via Swagger UI:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/auth/login` | User authentication |
| POST | `/api/v1/scans` | Submit URL for analysis |
| GET | `/api/v1/scans/{id}` | Retrieve scan results |
| GET | `/api/v1/scans/history` | Get scan history |

## Configuration

### Environment Variables

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/sentinelai

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your_key
URLSCAN_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key

# OpenRouter (AI Engine)
OPENROUTER_API_KEY=your_key
OPENROUTER_MODEL=your_model

# Security
JWT_SECRET_KEY=your_secret_key
JWT_ALGORITHM=HS256
```

## Development

### Backend Testing
```bash
cd backend
pytest
```

### Frontend Testing
```bash
cd frontend/dashboard
npm test
```

### Code Quality
```bash
# Linting
flake8 backend/
pylint backend/

# Type checking
mypy backend/
```

## Contributing

We welcome contributions! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Performance & Security

- **Rate Limiting**: API endpoints are rate-limited per user
- **Authentication**: JWT-based authentication with refresh tokens
- **Caching**: Intelligent caching of reputation data and analysis results
- **Logging**: Comprehensive audit logging for compliance
- **TLS/SSL**: All communications encrypted in production

## Troubleshooting

### Common Issues

**Backend won't start**
- Verify database connection: `DATABASE_URL` in `.env`
- Check API keys are valid: `VIRUSTOTAL_API_KEY`, etc.
- Ensure Python dependencies: `pip install -r requirements.txt`

**Frontend connection errors**
- Confirm backend is running: `curl http://localhost:8000/docs`
- Check CORS settings in backend configuration
- Verify API endpoint URL in frontend `.env`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation in `/docs`
- Review API docs at `http://localhost:8000/docs`

## Roadmap

- [ ] Enhanced ML-based threat scoring
- [ ] Real-time threat intelligence feeds
- [ ] Advanced analytics and reporting
- [ ] Multi-language support
- [ ] Mobile application
- [ ] Community threat sharing network

---

**Made with ❤️ for security teams worldwide**
4. `Technical Analysis`: raw indicators and component scores

## API Endpoints

- `GET /health`
- `GET /api/v1/health`
- `POST /api/v1/scan/url`
- `POST /api/v1/scan/page`
- `POST /api/v1/explain-deep`
- `GET /api/v1/history`
- `GET /api/v1/dashboard/stats`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`

## Key Environment Variables

- `SECRET_KEY`
- `DATABASE_URL`
- `VIRUSTOTAL_API_KEY`
- `URLSCAN_API_KEY`
- `ABUSEIPDB_API_KEY`
- `OPENROUTER_API_KEY`
- `SENTINELAI_NLP_MODEL`
- `REASON_WEIGHT_PHISHING_PROBABILITY`
- `REASON_WEIGHT_DOM_SUSPICION`
- `REASON_WEIGHT_CONTENT_SCAM_SCORE`
- `REASON_WEIGHT_REPUTATION_SCORE`
- `REASON_WEIGHT_REDIRECT_RISK`

## Local Run

Backend:

```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd frontend/dashboard
npm install
npm run dev
```

## Refactor Audit

Detailed audit and implemented refactor notes:

- `docs/sentinelai_refactor_audit.md`
