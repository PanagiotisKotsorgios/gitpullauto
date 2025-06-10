# GitHub Auto Uploader [gitpull_auto] 🚀

[![GitHub API](https://img.shields.io/badge/GitHub-API_Compliant-blue)](https://developer.github.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)


> Secure multi-user application for automated GitHub file synchronization with real-time monitoring using GitHub REST API

## 🔥 Features
- 🔐 **Secure Authentication**: PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations
- ⚡ **Real-time Monitoring**: Instant file synchronization using Watchdog
- 👥 **Multi-user Support**: Isolated environments with separate configurations
- 🔄 **Smart Syncing**: SHA-256 hashing to detect actual file changes
- 📝 **Customizable Workflows**: Ignore patterns, commit messages, branch selection
- 📊 **Activity Logging**: Per-user operation tracking

## ⚙️ GitHub API Implementation
This application demonstrates best practices for GitHub REST API usage:
```python
# API Request Example
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

data = {
    "message": commit_message,
    "content": base64.b64encode(content).decode(),
    "branch": branch,
    "sha": existing_file_sha  # For updates
}

response = requests.put(api_url, headers=headers, json=data)


```


## API Compliance Features

    ✅ Proper authentication headers

    ✅ Correct content encoding (Base64)

    ✅ SHA-based version control

    ✅ Rate limit awareness

    ✅ Proper error handling

    ✅ API version specification

    ✅ File size validation (<100MB GitHub limit)

## 🚀 Installation

```bash

# Clone repository
git clone https://github.com/yourusername/github-auto-uploader.git
cd github-auto-uploader

# Install dependencies
pip install -r requirements.txt

# Run application
python src/main.py
```

## ⚙️ Configuration

- Create user account in the application

- Generate GitHub Personal Access Token with repo scope:

        GitHub Token Settings

- Configure application:

        Set GitHub token in Settings

        Specify default repository (format: username/repo)

        Set monitoring paths and ignore patterns

## 🛡 Security Practices

```python

# Password hashing implementation
salt, key, iterations = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode('utf-8'),
    secrets.token_bytes(16),
    100000  # Iteration count
)
```

    🔒 Credentials never stored in plain text

    🔑 GitHub tokens encrypted at rest

    🗂 User-specific isolated storage

    🚫 Sensitive files excluded from version control (.gitignore)


## 📖 Usage Guide

Basic Workflow

- Login with your user credentials

- Configure GitHub token and repository

- Choose sync mode:

        Manual Upload: Select files/folders to upload

        Auto-Commit: Periodic folder scanning

        Real-time Sync: Instant file change detection

## Advanced Features

- Set file size limits to avoid large uploads

- Configure ignore patterns (e.g., *.tmp, *.log)

- Customize commit messages

- View detailed activity logs

## 📜 API Documentation

> This application uses these GitHub API endpoints:
Endpoint	Method	Usage
/repos/{owner}/{repo}/contents/{path}	PUT	Create/update files
/repos/{owner}/{repo}/contents/{path}	GET	Check file existence

> See full API Implementation Details for more information.

## 🤝 Contributing

We welcome contributions! Please follow these steps:

- Fork the repository

- Create your feature branch (git checkout -b feature/amazing-feature)

- Commit your changes (git commit -m 'Add some amazing feature')

- Push to the branch (git push origin feature/amazing-feature)

- Open a pull request

> See our Contribution Guidelines for more details.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

https://img.shields.io/badge/GitHub-Developer_Program-blue?logo=github






