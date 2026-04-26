# 🔐 Biubo WAF - 增強版本使用指南

## 新功能概述

本版本包含重大安全改進和本地化增強。

### 主要改進

✅ **安全加固**
- PBKDF2 密碼加密（100,000 次迭代）
- CSRF 令牌保護
- 登錄速率限制
- 密碼強度驗證
- 路徑遍歷防護

✅ **多語言支持**
- 繁體中文（預設）
- 簡體中文
- 英文

✅ **用戶體驗**
- 改進的 UI/UX
- 更好的錯誤消息
- 多語言儀表板

---

## 快速開始

### 1. 初始設置

首次運行 WAF 時，將顯示初始化頁面：

```bash
python main.py
```

訪問 `http://localhost:80/init`

**設置步驟**：
1. 設置管理員密碼（需滿足強度要求）
2. 配置 WAF 監聽端口
3. 配置代理網站
4. 完成初始化

### 2. 密碼要求

管理員密碼必須包含：
- ✅ 至少 8 個字符
- ✅ 至少一個大寫字母
- ✅ 至少一個小寫字母
- ✅ 至少一個數字
- ✅ 至少一個特殊字符 (!@#$%^&* 等)

**示例強密碼**：`Admin@123Secure!`

### 3. 登錄控制檯

訪問 `http://localhost/biubo-cgi/dashboard/login`

**登錄安全機制**：
- 最多 5 次失敗嘗試
- 15 分鐘自動鎖定
- CSRF 令牌驗證
- 會話超時 (30 分鐘)

### 4. 更改密碼

登錄後，可在 **設定** 標籤更改密碼：

1. 點擊 **系統全域設定**
2. 輸入舊密碼進行驗證
3. 輸入新密碼（滿足強度要求）
4. 確認新密碼
5. 點擊 **保存**

---

## 多語言使用

### 選擇語言

所有頁面都提供語言選擇器：

```
繁體中文 (zh-TW) - 默認
简体中文 (zh)
English (en)
```

### 語言持久化

選擇的語言會自動保存到瀏覽器本地存儲，下次訪問時自動恢復。

---

## 安全最佳實踐

### 1. 密碼管理
- ✅ 使用強且唯一的密碼
- ✅ 定期更改密碼
- ✅ 不共享管理員密碼
- ❌ 不使用字典詞彙

### 2. 會話安全
- ✅ 登錄後立即更改默認密碼
- ✅ 定期登出
- ✅ 使用 HTTPS（生產環境）
- ❌ 不在公共 WiFi 上訪問

### 3. 系統維護
- ✅ 定期備份配置
- ✅ 監控日誌
- ✅ 更新依賴項
- ❌ 不禁用安全功能

---

## 配置管理

### 設置位置

所有設置保存在 `config.json`：

```json
{
  "WAF_PORT": 80,
  "DASHBOARD_PASSWORD_HASH": "salt$hash...",
  "PROXY_MAP": {
    "example.com": "http://127.0.0.1:8080"
  },
  "LLM_MODEL": "qwen-plus",
  "LLM_BASE_URL": "https://dashscope.aliyuncs.com/compatible-mode/v1"
}
```

### 備份設置

定期備份 `config.json`：

```bash
cp config.json config.json.$(date +%Y%m%d).backup
```

---

## 故障排除

### 登錄被鎖定

如果收到 "登入次數過多" 的錯誤：
1. 等待 15 分鐘
2. 確認密碼正確
3. 檢查網路連接

### 密碼不符合要求

確保密碼包含：
- 大小寫字母（A-Z, a-z）
- 數字（0-9）
- 特殊字符（!@#$%^&* 等）
- 至少 8 個字符

### CSRF 驗證失敗

解決方案：
1. 清除瀏覽器 Cookie
2. 刷新頁面
3. 重新登錄

---

## 技術細節

### 密碼存儲

密碼使用 PBKDF2-SHA256 加密：
```python
ITERATIONS = 100000
ALGORITHM = 'sha256'
```

### 令牌安全

CSRF 令牌：
- 每次登錄刷新
- 24 小時過期
- 使用 URLsafe 編碼

### 會話管理

- 秘鑰隨機生成
- 嚴格的 Cookie 設置
- 無效令牌檢測

---

## API 端點

### 認證

```
POST /dashboard/api/login
  - password: 管理員密碼
  - X-CSRF-Token: CSRF 令牌

POST /dashboard/api/logout
  - (需要認證)

POST /dashboard/api/change-password
  - old_password: 舊密碼
  - new_password: 新密碼
  - confirm_password: 確認密碼
```

### 配置

```
GET /api/biubo/config
  - (需要認證)

POST /api/biubo/config
  - (需要認證和 CSRF 令牌)
  - WAF_PORT, PROXY_MAP, LLM_* 等
```

---

## 常見問題

**Q: 如何重置管理員密碼？**
A: 刪除 `config.json` 中的 `DASHBOARD_PASSWORD_HASH` 字段，重啟 WAF 時使用默認密碼 `admin123` 登錄。

**Q: 支援哪些語言？**
A: 目前支援繁體中文、簡體中文和英文。

**Q: 如何增加自訂語言？**
A: 在 HTML 文件的 `I18N` 對象中添加新語言代碼。

**Q: 會話多久超時？**
A: 未設置，但建議定期登出。

---

## 反饋和支持

- 🐛 報告漏洞：提交 GitHub Issue
- 💬 功能要求：討論區
- 📧 直接聯絡：admin@biubo.local

---

**版本**：v1.0.0-enhanced  
**更新日期**：2026年4月23日  
**維護者**：Biubo 開發團隊
