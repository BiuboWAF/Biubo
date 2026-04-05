import os
import json
import subprocess
import sys

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("=" * 60)
    print("       Biubo WAF - Unified Setup & Configuration")
    print("=" * 60)

def install_dependencies():
    print("\n[1/3] Checking dependencies...")
    if os.path.exists("requirements.txt"):
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("✓ Dependencies installed successfully.")
        except subprocess.CalledProcessError:
            print("! Error installing dependencies. Please check your internet connection and permissions.")
            input("Press Enter to continue anyway...")
    else:
        print("! requirements.txt not found. Skipping dependency installation.")

def create_directories():
    print("\n[2/3] Preparing system directories...")
    dirs = ["data", "page", "templates", "logs"]
    for d in dirs:
        if not os.path.exists(d):
            os.makedirs(d)
            print(f"  + Created {d}/")
    print("✓ Directories ready.")

def configure_settings():
    print("\n[3/3] Configuration Wizard")
    config_path = "config.json"
    
    # Load existing config if available
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except:
            pass

    def get_input(prompt, key, default):
        current = config.get(key, default)
        val = input(f"{prompt} [{current}]: ").strip()
        return val if val else current

    # Basic Settings
    config['WAF_PORT'] = int(get_input("WAF Listening Port", 'WAF_PORT', 80))
    config['DASHBOARD_PASSWORD'] = get_input("Dashboard Password", 'DASHBOARD_PASSWORD', "admin123")
    
    # LLM Settings
    print("\n-- LLM Configuration (Optional) --")
    config['API_KEY'] = get_input("LLM API Key", 'API_KEY', "")
    config['LLM_BASE_URL'] = get_input("LLM Base URL", 'LLM_BASE_URL', "https://dashscope.aliyuncs.com/compatible-mode/v1")
    config['LLM_MODEL'] = get_input("LLM Model", 'LLM_MODEL', "qwen-plus")

    # Proxy Map
    print("\n-- Proxy Configuration --")
    print("Enter the domains you want to protect and their backend server URLs.")
    print("Example: example.com -> http://127.0.0.1:8080")
    
    proxy_map = config.get('PROXY_MAP', {})
    if proxy_map:
        print(f"Current proxy map: {proxy_map}")
        change = input("Do you want to modify the proxy map? (y/N): ").lower() == 'y'
    else:
        change = True

    if change:
        new_proxy_map = {}
        while True:
            domain = input("Domain (e.g., example.com) [leave empty to finish]: ").strip()
            if not domain:
                break
            backend = input(f"Backend URL for {domain} (e.g., http://127.0.0.1:8080): ").strip()
            if not backend:
                print("! Backend URL cannot be empty. Skipping.")
                continue
            new_proxy_map[domain] = backend
        
        if new_proxy_map:
            config['PROXY_MAP'] = new_proxy_map

    # Save Config
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    
    print(f"\n✓ Configuration saved to {config_path}")

def main():
    clear_screen()
    print_banner()
    
    install_dependencies()
    create_directories()
    configure_settings()
    
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("To start Biubo WAF, run: python main.py")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(0)
