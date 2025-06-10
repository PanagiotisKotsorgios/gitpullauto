# GitHub API Implementation Details

## 🔐 Authentication
```
headers = {
    "Authorization": f"token {token}",  # Bearer token authentication
    "Accept": "application/vnd.github.v3+json",  # Correct media type
    "X-GitHub-Api-Version": "2022-11-28",  # API version pinning
    "User-Agent": "GitHub-Auto-Uploader/1.0"  # Required header
}
```

## 📦 File Operations

> Upload/Update File

```python

def upload_file_to_github(token, repo, branch, local_file, repo_path, commit_message):
    # Base64 encode content
    with open(local_file, "rb") as f:
        content = base64.b64encode(f.read()).decode()
    
    # Check existing file for SHA
    r = requests.get(
        f"https://api.github.com/repos/{repo}/contents/{repo_path}",
        headers=headers,
        params={"ref": branch}
    )
    
    # Get SHA if file exists
    sha = r.json().get('sha') if r.status_code == 200 else None
    
    # Prepare payload
    data = {
        "message": commit_message,
        "content": content,
        "branch": branch,
    }
    if sha:
        data["sha"] = sha  # Required for updates

```

### Key Implementation Notes

- Base64 Encoding: Required by GitHub API for file content

- SHA Tracking: Essential for file version control

- Branch Specification: Allows targeting specific branches

- Proper Error Handling: Catches API errors and network issues


## ⚖️ Rate Limit Handling

```python

# Check rate limit headers
rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

if rate_limit_remaining < 10:
    reset_time = rate_limit_reset - time.time()
    wait_time = max(reset_time, 0) + 10  # Add buffer
    print(f"Approaching rate limit. Waiting {wait_time:.1f} seconds")
    time.sleep(wait_time)
```

## 🚫 Error Handling

```python

# Handle API errors
if response.status_code == 403:
    if "rate limit" in response.text:
        handle_rate_limit(response)
    else:
        log_error("Permission error: Check token scope")
elif response.status_code == 404:
    log_error("Resource not found: Verify repo/path")
elif response.status_code >= 500:
    log_error("GitHub server error - retrying after delay")
    time.sleep(30)
```

## ✅ Compliance Checklist

- Proper authentication headers

- API version specification

- User-Agent header included

- Base64 content encoding

- SHA-based version control

- File size validation (<100MB)

- Rate limit handling

- Error classification

- Retry mechanism for server errors
