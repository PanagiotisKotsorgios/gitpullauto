# Developer Guide

## 🛠 Development Setup

```bash
# Create virtual environment
python -m venv venv

# Activate environment (Linux/macOS)
source venv/bin/activate

# Activate environment (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development tools
pip install pytest watchdog
```

## 🧪 Testing

```bash

# Run unit tests
pytest tests/

# Test coverage report
pytest --cov=src --cov-report=html
```

## 🧩 Architecture Overview
```

src/
├── main.py                 
```

## 📜 Code Standards

- PEP 8 Compliance: Follow Python style guide

- Type Hinting: All functions and variables

- Docstrings: Google-style for public methods

```python

    def upload_file(token: str, repo: str, path: str) -> bool:
```

        
        Args:
            token: GitHub access token
            repo: Repository in 'owner/repo' format
            path: Local file path
            
        Returns:
            True if upload succeeded
        """
```
```

-  Modular Design: Single-responsibility components

## 🚀 Deployment

Production Build
```bash

# Create standalone executable
pip install pyinstaller
pyinstaller --onefile src/main.py

Docker Build
dockerfile

FROM python:3.10-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

CMD ["python", "src/main.py"]
```

## 🤝 Contribution Workflow

- Fork repository

- Create feature branch (feat/new-feature)

- Implement changes with tests

- Update documentation

- Submit pull request

