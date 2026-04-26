#!/usr/bin/env python3
"""
忘記密碼重置腳本
Forgot Password Reset Script

使用方法 / Usage:
    python reset_password.py

此腳本會將 Dashboard 密碼重置為預設密碼。
This script will reset the Dashboard password to default.
"""

import json
import os

CONFIG_FILE = "config.json"
DEFAULT_PASSWORD = "biubo123456"

def reset_password():
    """重置密碼為預設值 / Reset password to default"""
    print("=" * 50)
    print("忘記密碼重置工具 / Forgot Password Reset Tool")
    print("=" * 50)
    
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ 錯誤：找不到 {CONFIG_FILE}")
        print(f"❌ Error: {CONFIG_FILE} not found")
        return False
    
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        
        print(f"📖 讀取配置文件: {CONFIG_FILE}")
        print(f"📖 Reading config file: {CONFIG_FILE}")
        
        # 重置密碼哈希為空
        config["DASHBOARD_PASSWORD_HASH"] = ""
        
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"✅ 密碼已重置為預設值")
        print(f"✅ Password reset to default")
        print(f"🔑 預設密碼: {DEFAULT_PASSWORD}")
        print(f"🔑 Default password: {DEFAULT_PASSWORD}")
        print()
        print("⚠️  請重新啟動 WAF 服務以應用變更")
        print("⚠️  Please restart WAF service to apply changes")
        
        return True
    except Exception as e:
        print(f"❌ 錯誤：{e}")
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    reset_password()
