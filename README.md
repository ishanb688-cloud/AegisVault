# AegisVault

### Understand Password Risks. Strengthen Credential Security.

AegisVault is a Python-based cybersecurity toolkit designed for authorized, offline password security assessment. It brings hash inspection, dictionary-based candidate generation, bounded password verification, strength analysis, and security reporting into one integrated assessment workflow.

The project aims to make credential security testing understandable, structured, and evidence-based.

---

## Overview

Password security is an important part of protecting digital systems. Weak passwords, predictable patterns, and inadequate password-storage practices can expose organizations to credential-related risks.

AegisVault provides a controlled environment to examine these risks using authorized test data.

Instead of presenting separate tools with disconnected results, AegisVault coordinates its assessment components and produces a unified security report.

## Key Components

| Component | Responsibility |
|---|---|
| Dictionary Engine | Generates bounded password candidates and common variations. |
| Hash Inspector | Identifies supported hash formats and parses supported credential-record formats. |
| Verification Engine | Performs bounded offline candidate verification for supported formats. |
| Strength Analyzer | Evaluates verified candidate passwords using conservative strength indicators. |
| Report Engine | Produces findings, recommendations, and assessment limitations. |
| Assessment Controller | Coordinates the complete assessment workflow. |

These components operate as one integrated assessment system.

## Features

- Offline credential security assessment.
- Hash-format inspection and identification.
- Linux shadow-style record parsing.
- Windows SAM-style text export parsing.
- Dictionary-based candidate generation.
- Common password candidate testing.
- Bounded offline SHA-256 candidate verification.
- Password predictability analysis for verified candidates.
- Consolidated security findings.
- Recommendations for improving password policies.
- REST API powered by FastAPI.

## Technology Stack

**Backend**
- Python
- FastAPI
- Pydantic
- Uvicorn

**Frontend**
- HTML
- CSS
- JavaScript

**Testing**
- Pytest
- HTTPX

**Version Control**
- Git
- GitHub

## Architecture

The application follows a unified assessment pipeline:

```text
        User Input
            |
            v
     Assessment Controller
            |
            v
       Hash Inspector
            |
            v
      Dictionary Engine
            |
            v
    Verification Engine
            |
            v
     Strength Analyzer
            |
            v
       Report Engine
            |
            v
     Unified Security Report
```

Strength analysis is performed only when a candidate has actually been verified.

## Project Structure

```text
AegisVault/
│
├── app.py
├── requirements.txt
├── render.yaml
│
├── index.html
│
├── core/
│   ├── __init__.py
│   ├── models.py
│   ├── hash_inspector.py
│   ├── dictionary_engine.py
│   ├── verification.py
│   ├── strength_analyzer.py
│   ├── report.py
│   └── assessment.py
│
└── tests/
    └── test_assessment.py
```

## Installation

### 1. Clone the repository

```bash
git clone -b fresh-rebuild https://github.com/ishanb688-cloud/AegisVault.git
```

### 2. Open the project directory

```bash
cd AegisVault
```

### 3. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 5. Start the application

```powershell
python -m uvicorn app:app --reload --port 8000
```

Open the application:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

Health endpoint:

```text
http://127.0.0.1:8000/api/health
```

## API

The unified assessment endpoint is:

```http
POST /api/assessment
```

It accepts structured assessment input and returns a consolidated report.

The current request model supports:

- `records`: credential or hash records supplied for inspection.
- `candidate_words`: bounded candidate passwords for offline verification.
- `include_common_candidates`: whether the built-in common candidate sample should be included.

Use the interactive API documentation at `/docs` to inspect the exact request schema and response structure.

## Testing

Run the automated test suite using:

```powershell
python -m pytest -v
```

Tests are intended to cover:

- Application health checks.
- Supported SHA-256 candidate verification.
- Unmatched candidate handling.
- Ambiguous hash identification.
- Locked account handling.

Test execution and results should be verified in the local environment before presenting the project as fully tested.

## Security and Ethical Use

AegisVault is intended strictly for:

- Authorized security assessments.
- Offline laboratory experiments.
- Synthetic credential datasets.
- Educational cybersecurity demonstrations.
- Password-policy evaluation.

**Important safeguards:**

- Do not use credentials belonging to other people or organizations without explicit authorization.
- Do not use the application for unauthorized account access.
- Do not upload real credential databases to public demonstrations.
- Use synthetic test data when demonstrating the project publicly.
- Keep all testing offline and within a controlled environment.

## Current Limitations

AegisVault is under active development.

The current implementation has important limitations:

- Candidate verification currently supports raw SHA-256 only.
- Several recognized password-hashing formats are identified but are not yet verified.
- A 32-character hexadecimal digest may be ambiguous without reliable source context.
- Failure to find a matching candidate does not prove that a password is strong.
- Strength estimates are heuristic indicators, not guarantees of actual password entropy.
- Windows SAM-style parsing currently concerns supplied text exports, not automated extraction from live Windows systems.
- Automated live credential extraction, online attacks, and unrestricted brute-force operations are not supported.

These limitations are documented to keep assessment results accurate and prevent misleading security conclusions.

## Future Development

Planned improvements include:

- Additional secure password-hashing format support.
- More comprehensive hash-format identification.
- Improved dictionary mutation strategies.
- Better password-policy evaluation.
- Expanded automated test coverage.
- More detailed evidence-based security reports.
- Improved assessment visualization.
- Additional documentation and demonstration datasets.

## Project Objective

The objective of AegisVault is to demonstrate how Python can be used to build a modular, integrated cybersecurity assessment application.

The project combines practical programming, cybersecurity concepts, API development, controlled testing, and security reporting into one application.

---

## Author

**Ishan Bhat**

Computer Science Engineering Student

GitHub: [ishanb688-cloud](https://github.com/ishanb688-cloud)

**Project:** AegisVault

---

*Built for cybersecurity learning, authorized assessment, and responsible security research.*
