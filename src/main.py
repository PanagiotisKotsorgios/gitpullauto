import os
import requests
import base64
import time
import threading
import json
import hashlib
import fnmatch
import sys
import secrets
import getpass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -------------------- SECURITY FUNCTIONS --------------------
def hash_password(password, salt=None):
    """Hash a password with a salt using PBKDF2-HMAC-SHA256"""
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # Use a high iteration count to make brute-force attacks harder
    iterations = 100000
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    return salt, key, iterations

def verify_password(stored_salt, stored_key, stored_iterations, password):
    """Verify a password against stored hash"""
    salt_bytes = base64.b64decode(stored_salt)
    key_bytes = base64.b64decode(stored_key)
    
    # Generate hash with the same parameters
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        stored_iterations
    )
    return new_key == key_bytes

# -------------------- USER MANAGEMENT --------------------
def get_user_dir(username):
    """Get directory path for a user"""
    user_dir = os.path.join("users", username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def get_user_settings_file(username):
    """Get path to user settings file"""
    return os.path.join(get_user_dir(username), "github_uploader_settings.json")

def get_user_log_file(username):
    """Get path to user log file"""
    return os.path.join(get_user_dir(username), "upload_log.txt")

def get_user_state_file(username):
    """Get path to user state file"""
    return os.path.join(get_user_dir(username), "uploader_state.json")

def get_user_auth_file(username):
    """Get path to user authentication file"""
    return os.path.join(get_user_dir(username), "user_auth.json")

def save_user_auth(username, salt, key, iterations):
    """Save authentication data for a user"""
    auth_file = get_user_auth_file(username)
    auth_data = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "hash": base64.b64encode(key).decode('utf-8'),
        "iterations": iterations
    }
    with open(auth_file, "w") as f:
        json.dump(auth_data, f, indent=2)

def load_user_auth(username):
    """Load authentication data for a user"""
    auth_file = get_user_auth_file(username)
    if os.path.exists(auth_file):
        with open(auth_file, "r") as f:
            return json.load(f)
    return None

# -------------------- CORE FUNCTIONALITY --------------------
def clear_console():
    """Clear the console based on the operating system"""
    os.system('cls' if os.name == 'nt' else 'clear')

def save_settings(settings, username):
    settings_file = get_user_settings_file(username)
    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)

def load_settings(username):
    settings_file = get_user_settings_file(username)
    if os.path.exists(settings_file):
        with open(settings_file, "r") as f:
            return json.load(f)
    return {}

def log_upload(msg, username):
    log_file = get_user_log_file(username)
    with open(log_file, "a") as f:
        f.write(f"{time.ctime()}: {msg}\n")

def input_nonempty(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value

def get_github_headers(token):
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

def upload_file_to_github(token, repo, branch, local_file, repo_path, commit_message, username):
    api_url = f"https://api.github.com/repos/{repo}/contents/{repo_path}"
    headers = get_github_headers(token)

    with open(local_file, "rb") as f:
        content = base64.b64encode(f.read()).decode()

    # Check if file exists to get sha for update
    r = requests.get(api_url, headers=headers, params={"ref": branch})
    sha = r.json().get('sha') if r.status_code == 200 else None

    data = {
        "message": commit_message,
        "content": content,
        "branch": branch,
    }
    if sha:
        data["sha"] = sha

    resp = requests.put(api_url, headers=headers, json=data)
    if resp.status_code not in [200, 201]:
        print(f"Failed to upload {repo_path}: {resp.text}")
        log_upload(f"Failed: {repo_path}: {resp.text}", username)
        return False
    else:
        print(f"Uploaded {repo_path}")
        log_upload(f"Uploaded: {repo_path}", username)
        return True

def upload_folder(token, repo, branch, local_folder, repo_folder, commit_message, username, ignore_patterns=None):
    for root, dirs, files in os.walk(local_folder):
        rel_root = os.path.relpath(root, local_folder)
        repo_root = os.path.normpath(os.path.join(repo_folder, rel_root)).replace("\\", "/")
        for file in files:
            if ignore_patterns and any(file.endswith(p) for p in ignore_patterns):
                continue
            local_file_path = os.path.join(root, file)
            repo_file_path = os.path.normpath(os.path.join(repo_root, file)).replace("\\", "/")
            upload_file_to_github(token, repo, branch, local_file_path, repo_file_path, commit_message, username)

# -------------------- ADVANCED FEATURES --------------------
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, callback, ignore_patterns=None, username=None):
        self.callback = callback
        self.ignore_patterns = ignore_patterns or []
        self.username = username
    
    def on_modified(self, event):
        if not event.is_directory:
            self.process_event(event)
    
    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event)
    
    def on_moved(self, event):
        if not event.is_directory:
            self.process_event(event)
    
    def process_event(self, event):
        file_path = event.src_path
        filename = os.path.basename(file_path)
        
        # Check ignore patterns
        if any(fnmatch.fnmatch(filename, pattern) for pattern in self.ignore_patterns):
            return
            
        self.callback(file_path, self.username)

def save_state(state, username):
    state_file = get_user_state_file(username)
    with open(state_file, "w") as f:
        json.dump(state, f)

def load_state(username):
    state_file = get_user_state_file(username)
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            return json.load(f)
    return {"file_hashes": {}}

def get_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def advanced_auto_commit(settings, stop_event, username):
    print(f"Advanced auto-commit mode started for {username}. Monitoring {settings['monitor_path']}...")
    log_upload(f"Advanced auto-commit started for {settings['monitor_path']}", username)
    
    # Load previous state
    state = load_state(username)
    file_hashes = state.get("file_hashes", {})
    
    # File change callback
    def upload_if_changed(file_path, username):
        if not os.path.isfile(file_path):
            return
            
        # Calculate relative path
        rel_path = os.path.relpath(file_path, settings['monitor_path'])
        repo_path = os.path.join(settings['monitor_repo_path'], rel_path).replace("\\", "/")
        
        # Get file hash
        try:
            current_hash = get_file_hash(file_path)
        except Exception as e:
            log_upload(f"Error hashing {file_path}: {str(e)}", username)
            return
            
        # Check if file has changed
        if file_path in file_hashes and file_hashes[file_path] == current_hash:
            return
            
        # Upload file
        success = upload_file_to_github(
            settings['token'],
            settings['repo'],
            settings['branch'],
            file_path,
            repo_path,
            settings.get('monitor_commit_message', 'Auto update'),
            username
        )
        
        # Update state if successful
        if success:
            file_hashes[file_path] = current_hash
            state["file_hashes"] = file_hashes
            save_state(state, username)
    
    # Set up file monitoring
    event_handler = ChangeHandler(
        upload_if_changed,
        ignore_patterns=settings.get('monitor_ignore_patterns', []),
        username=username
    )
    observer = Observer()
    observer.schedule(event_handler, settings['monitor_path'], recursive=True)
    observer.start()
    
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.stop()
    observer.join()
    print(f"Advanced auto-commit mode stopped for {username}.")
    log_upload("Advanced auto-commit stopped", username)

# -------------------- SETTINGS MENUS --------------------
def settings_menu(settings, username):
    while True:
        if settings.get('clear_screen', True):
            clear_console()
        
        print(f"\n--- Settings ({username}) ---")
        print(f"1. GitHub token (set: {'Yes' if settings.get('token') else 'No'})")
        print(f"2. Repo (set: {settings.get('repo', '')})")
        print(f"3. Branch (set: {settings.get('branch', 'main')})")
        print(f"4. Default commit message (set: {settings.get('commit_message', 'Auto upload')})")
        print(f"5. Ignore file patterns (comma separated, e.g.: .tmp,.log) (set: {settings.get('ignore_patterns', [])})")
        print(f"6. Auto-upload interval (seconds) (set: {settings.get('interval', 30)})")
        print(f"7. Clear screen after actions (set: {'Yes' if settings.get('clear_screen', True) else 'No'})")
        print("8. Change password")
        print("0. Back to main menu")
        
        choice = input("Choose: ").strip()
        if choice == "1":
            settings['token'] = input_nonempty("Enter GitHub token: ")
        elif choice == "2":
            settings['repo'] = input_nonempty("Enter repo (e.g., user/repo): ")
        elif choice == "3":
            settings['branch'] = input("Enter branch [main]: ").strip() or "main"
        elif choice == "4":
            settings['commit_message'] = input("Enter default commit message: ").strip() or "Auto upload"
        elif choice == "5":
            patterns = input("Enter ignore patterns (comma separated): ").strip()
            settings['ignore_patterns'] = [p.strip() for p in patterns.split(',') if p.strip()]
        elif choice == "6":
            try:
                settings['interval'] = int(input("Enter interval in seconds [30]: ").strip() or 30)
            except ValueError:
                print("Must be an integer")
        elif choice == "7":
            toggle = input("Clear screen after actions? (y/n) [y]: ").lower().strip() or 'y'
            settings['clear_screen'] = (toggle == 'y')
        elif choice == "8":
            change_password(username)
        elif choice == "0":
            save_settings(settings, username)
            return
        else:
            print("Invalid choice!")

def advanced_settings_menu(settings, username):
    while True:
        if settings.get('clear_screen', True):
            clear_console()
        
        print(f"\n--- Advanced Settings ({username}) ---")
        print("1. File monitoring path")
        print(f"  Current: {settings.get('monitor_path', 'Not set')}")
        print("2. Monitoring target repo path")
        print(f"  Current: {settings.get('monitor_repo_path', 'Not set')}")
        print("3. Monitoring commit message")
        print(f"  Current: {settings.get('monitor_commit_message', 'Auto update')}")
        print("4. Max file size for monitoring (MB)")
        print(f"  Current: {settings.get('max_file_size', 10)}")
        print("5. Ignore patterns for monitoring (comma separated)")
        print(f"  Current: {', '.join(settings.get('monitor_ignore_patterns', []))}")
        print("0. Back to main menu")
        
        choice = input("Choose: ").strip()
        if choice == "1":
            path = input("Enter path to monitor: ").strip()
            if os.path.isdir(path):
                settings['monitor_path'] = path
            else:
                print("Invalid directory!")
        elif choice == "2":
            settings['monitor_repo_path'] = input("Enter repo path for monitored files: ").strip()
        elif choice == "3":
            settings['monitor_commit_message'] = input("Enter commit message for monitored files: ").strip()
        elif choice == "4":
            try:
                settings['max_file_size'] = int(input("Enter max file size in MB: ").strip())
            except ValueError:
                print("Invalid number!")
        elif choice == "5":
            patterns = input("Enter ignore patterns (comma separated): ").strip()
            settings['monitor_ignore_patterns'] = [p.strip() for p in patterns.split(',') if p.strip()]
        elif choice == "0":
            save_settings(settings, username)
            return
        else:
            print("Invalid choice!")

# -------------------- USER MANAGEMENT --------------------
def user_menu():
    clear_console()
    print("\n=== GitHub Auto Uploader ===")
    print("[1] Login")
    print("[2] Create new user")
    print("[3] List all users")
    print("[0] Exit")
    
    choice = input("Choose: ").strip()
    return choice

def create_new_user():
    clear_console()
    print("\n=== Create New User ===")
    username = input_nonempty("Enter username: ")
    
    # Check if user already exists
    user_dir = get_user_dir(username)
    if os.path.exists(user_dir):
        print(f"User '{username}' already exists!")
        time.sleep(1)
        return None
    
    # Get password securely
    while True:
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password == confirm:
            break
        print("Passwords don't match! Please try again.")
    
    # Create user directory
    os.makedirs(user_dir, exist_ok=True)
    
    # Hash and store password
    salt, key, iterations = hash_password(password)
    save_user_auth(username, salt, key, iterations)
    
    # Create default settings
    settings = {
        'branch': 'main',
        'commit_message': 'Auto upload',
        'ignore_patterns': [],
        'interval': 30,
        'clear_screen': True,
        'monitor_ignore_patterns': [],
        'max_file_size': 10,
        'monitor_commit_message': 'Auto update'
    }
    save_settings(settings, username)
    
    print(f"User '{username}' created successfully!")
    time.sleep(1)
    return username

def authenticate_user(username):
    """Authenticate a user with password"""
    auth_data = load_user_auth(username)
    if not auth_data:
        print("User authentication data missing!")
        time.sleep(1)
        return False
    
    # Get password securely
    password = getpass.getpass(f"Enter password for {username}: ")
    
    # Verify password
    if verify_password(
        auth_data['salt'],
        auth_data['hash'],
        auth_data['iterations'],
        password
    ):
        return True
    
    print("Invalid password!")
    time.sleep(1)
    return False

def list_users():
    clear_console()
    print("\n=== Existing Users ===")
    if not os.path.exists("users"):
        print("No users found!")
        input("\nPress Enter to continue...")
        return
    
    users = [d for d in os.listdir("users") if os.path.isdir(os.path.join("users", d))]
    if not users:
        print("No users found!")
        input("\nPress Enter to continue...")
        return
    
    for i, user in enumerate(users, 1):
        print(f"{i}. {user}")
    
    input("\nPress Enter to continue...")

def change_password(username):
    """Change a user's password"""
    clear_console()
    print(f"\n=== Change Password for {username} ===")
    
    # Verify current password
    if not authenticate_user(username):
        return
    
    # Get new password
    while True:
        new_password = getpass.getpass("Enter new password: ")
        confirm = getpass.getpass("Confirm new password: ")
        if new_password == confirm:
            break
        print("Passwords don't match! Please try again.")
    
    # Update password
    salt, key, iterations = hash_password(new_password)
    save_user_auth(username, salt, key, iterations)
    
    print("Password changed successfully!")
    time.sleep(1)

# -------------------- MAIN APPLICATION --------------------
def main_user(username):
    settings = load_settings(username)
    
    stop_event = threading.Event()
    auto_thread = None
    advanced_monitor_thread = None

    while True:
        if settings.get('clear_screen', True):
            clear_console()
        
        print(f"\n=== GitHub Auto Uploader ({username}) ===")
        print("[1] Upload file/folder now")
        print("[2] Enable/disable basic auto-commit mode")
        print("[3] Settings")
        print("[4] View upload log")
        print("[5] Advanced file monitoring")
        print("[6] Advanced settings")
        print("[7] Switch user")
        print("[8] Change password")
        print("[0] Exit")
        
        choice = input("Choose: ").strip()
        
        if choice == "1":
            local_path = input_nonempty("Enter local file/folder path to upload: ")
            repo_path = input_nonempty("Enter target path in the repo (e.g. data/ or filename.ext): ")
            commit_message = input("Enter commit message [{}]: ".format(
                settings.get('commit_message', 'Auto upload'))).strip() or settings.get('commit_message', 'Auto upload')
            
            if os.path.isdir(local_path):
                upload_folder(settings['token'], settings['repo'], settings['branch'], 
                             local_path, repo_path, commit_message, 
                             username, settings.get('ignore_patterns'))
            else:
                upload_file_to_github(settings['token'], settings['repo'], settings['branch'], 
                                     local_path, repo_path, commit_message, username)
            
            if settings.get('clear_screen', True):
                time.sleep(2)  # Give user time to see success message
                clear_console()
        
        elif choice == "2":
            if auto_thread and auto_thread.is_alive():
                print("Disabling auto-commit mode...")
                stop_event.set()
                auto_thread.join()
                auto_thread = None
                time.sleep(1)
            else:
                print("Enabling auto-commit mode...")
                local_path = input_nonempty("Enter local folder to watch: ")
                repo_path = input_nonempty("Enter target repo path for folder: ")
                settings['local_path'] = local_path
                settings['repo_path'] = repo_path
                stop_event.clear()
                auto_thread = threading.Thread(target=auto_commit, args=(settings, stop_event, username))
                auto_thread.start()
                time.sleep(1)
        
        elif choice == "3":
            settings_menu(settings, username)
        
        elif choice == "4":
            log_file = get_user_log_file(username)
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    print("\n=== Upload Log ===\n")
                    print(f.read())
                    input("\nPress Enter to continue...")
            else:
                print("No logs yet.")
                time.sleep(1)
        
        elif choice == "5":  # Advanced file monitoring
            if advanced_monitor_thread and advanced_monitor_thread.is_alive():
                print("Stopping advanced monitoring...")
                stop_event.set()
                advanced_monitor_thread.join()
                advanced_monitor_thread = None
                time.sleep(1)
            else:
                if 'monitor_path' not in settings or not os.path.isdir(settings['monitor_path']):
                    print("Monitoring path not configured!")
                    path = input("Enter path to monitor: ").strip()
                    if os.path.isdir(path):
                        settings['monitor_path'] = path
                    else:
                        print("Invalid path!")
                        time.sleep(1)
                        continue
                
                if 'monitor_repo_path' not in settings or not settings['monitor_repo_path']:
                    settings['monitor_repo_path'] = input("Enter repo path for monitored files: ").strip()
                
                print("Starting advanced file monitoring...")
                stop_event.clear()
                advanced_monitor_thread = threading.Thread(
                    target=advanced_auto_commit, 
                    args=(settings, stop_event, username)
                )
                advanced_monitor_thread.start()
                time.sleep(1)
        
        elif choice == "6":  # Advanced settings
            advanced_settings_menu(settings, username)
        
        elif choice == "7":
            save_settings(settings, username)
            return True  # Signal to switch user
        
        elif choice == "8":
            change_password(username)
        
        elif choice == "0":
            if auto_thread and auto_thread.is_alive():
                stop_event.set()
                auto_thread.join()
            if advanced_monitor_thread and advanced_monitor_thread.is_alive():
                stop_event.set()
                advanced_monitor_thread.join()
            save_settings(settings, username)
            print("Bye!")
            return False  # Signal to exit
        
        else:
            print("Invalid choice!")
            time.sleep(1)

def main():
    # Create users directory if it doesn't exist
    os.makedirs("users", exist_ok=True)
    
    current_user = None
    
    while True:
        if current_user is None:
            choice = user_menu()
            
            if choice == "1":  # Login
                username = input_nonempty("Enter username: ")
                user_dir = get_user_dir(username)
                if not os.path.exists(user_dir):
                    print(f"User '{username}' does not exist!")
                    time.sleep(1)
                elif authenticate_user(username):
                    current_user = username
            
            elif choice == "2":  # Create new user
                username = create_new_user()
                if username:
                    current_user = username
            
            elif choice == "3":  # List users
                list_users()
            
            elif choice == "0":  # Exit
                print("Exiting application...")
                break
        else:
            switch_user = main_user(current_user)
            if switch_user:
                current_user = None  # Return to user selection
            else:
                break  # Exit program

if __name__ == "__main__":
    main()
