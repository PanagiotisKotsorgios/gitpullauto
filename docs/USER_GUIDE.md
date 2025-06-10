# User Guide

## 🚀 Getting Started

1. **Installation**:
   ```bash
   git clone https://github.com/yourusername/github-auto-uploader.git
   cd github-auto-uploader
   pip install -r requirements.txt
   python src/main.py
   ```

2. **Create Account**:

  ```
  1. Select "Create new user"

  2. Choose secure password
```


3. **Configure GitHub**:

```
1. Generate token at github.com/settings/tokens

2. Select repo scope

3. Enter token in Settings > GitHub Token

```

## 🔄 Modes of Operation

`Manual Upload`

    1. Select "Upload file/folder now"

    2. Enter local path

    3. Specify target repository path

    4. Add commit message

## Auto-Commit Mode

    1. Enable auto-commit

    2. Set folder to watch

    3. Configure scan interval

    4. Set target repository path

## Real-time Monitoring

    1. Enable advanced monitoring

    2. Set folder to monitor

    3. Configure ignore patterns

    4. Set max file size

## ⚠️ Troubleshooting

> Upload failed	Verify token has repo scope

> File not detected	Check ignore patterns in settings

> "Invalid path" error	Confirm directory exists

> Rate limit errors	Wait or use token with higher limits

> Permission denied	Check file permissions on monitored folders

## 💡 Pro Tips

- Use .gitignore-style patterns for ignores: *.log, temp_*

- Set commit messages with placeholders: Auto-sync: {filename}

- Monitor large files separately with size limits

- Review logs regularly in user directory
