# Codex Desktop — 連接 Turnstile APIM

本文件說明如何在 Windows 環境中，透過 Microsoft Entra ID 驗證，將 **Codex CLI** 或 **ChatGPT Desktop 的 Codex 模式** 連接至 Turnstile API Management（APIM）Gateway。

Turnstile 提供統一的模型存取入口，負責身分驗證、模型授權、流量治理與使用量控管。使用者不需要直接管理模型 API Key，只需完成企業帳號登入及 Codex 設定。

**設定流程**

1. **管理員**：設定 Entra ID、APIM Policy、模型權限與 Token Resolver。
2. **使用者**：安裝 Token Resolver、完成登入、設定 Codex 並驗證連線。

---

## Part 1. 管理員設定（Administrator Setup）

本節供 Gateway / Entra 管理員使用。所有設定只需在首次部署或相關配置變更時執行。

### 1.1 環境設定資訊

目前 Turnstile Gateway 的參考配置如下：

| 項目 | 設定值 |
|---|---|
| Tenant ID | `b9bbf971-ad4d-4759-acf5-93dc3599c3f6` |
| Gateway API / Audience | `7398a26d-832a-4a9d-889f-04b3c74218c4` |
| Gateway Scope | `api://7398a26d-832a-4a9d-889f-04b3c74218c4/Model.Invoke` |
| 共用 Employee Client ID（Claude Code / Codex） | `be989933-a2eb-42ef-9ae6-72024b01a997` |
| Gateway Base URL | `https://kurt-apim.azure-api.net/vicadopted/llm` |
| Model Alias | `gpt-5.6-luna-foundry-6e35e30c` |
| Codex Provider ID | `turnstile` |

Gateway Base URL 必須包含已發布的 API Path。Codex 使用 Responses API，實際推論請求會發送至該 Base URL 底下的 `/responses`。

### 1.2 設定 Entra ID App Registration

Codex 與 Claude Code 共用同一個 Employee Public Client App Registration 取得 Gateway Access Token，不需要為不同工具建立獨立 registration。

**設定步驟**

1. 前往 **Microsoft Entra admin center → App registrations**
2. 選擇 `employeeClientId` 對應的共用 App Registration；尚未建立時才新增
3. 將應用程式配置為支援組織核准登入流程的 Public Client
4. 在 **API permissions → Add a permission → My APIs** 中選擇 `Turnstile E2E Model API`
5. 加入 Delegated Permission：`Model.Invoke`。
6. 執行 **Grant admin consent**，確認狀態為 `Granted for the tenant`

完成後，應確認以下資訊：

| 驗證項目 | 預期值 |
|---|---|
| Client ID | `be989933-a2eb-42ef-9ae6-72024b01a997`（與 `employeeClientId` 相同） |
| Permission | `Model.Invoke` |
| Permission Type | Delegated |
| Admin Consent | Granted |

### 1.3 設定 APIM Admission Policy

Turnstile APIM 只允許 `employeeClientId` 指定的共用 Client ID，並驗證 Access Token 的必要 Claims。Claude Code 與 Codex 的 Token Resolver 都必須使用此 Client ID。

參考配置：

| Application | Client ID |
|---|---|
| Claude Code / Codex 共用 | `be989933-a2eb-42ef-9ae6-72024b01a997` |

APIM Policy 應驗證：

- `azp`：請求來自允許的 OAuth Client。
- `aud`：Token Audience 為 Turnstile Gateway API。
- `scp`：包含 `Model.Invoke`。
- `tid`：符合允許的 Entra Tenant。

參數檔使用以下設定：
- `employeeClientId`：填入共用 Employee Public Client 的 Client ID。
- `employeeAudience`：維持 Gateway Model API 的 audience，不要改成共用 Client ID。
- `employeeClientMap`：以共用 Client ID 對應同一個流量顯示名稱，例如 `Employee AI Tools`。
- `employeeSurfaceMap`：不需要按工具區分時保持 `[]`。

既有環境新增 Codex 時，只需讓其 Token Resolver 使用既有的 `employeeClientId`，不必新增允許的 Client ID。

### 1.4 發布模型與設定存取權限

在 Turnstile Control Plane 中：

1. 確認模型已發布至對應 Gateway Route。
2. 確認 Model Alias 正確。
3. 將模型指派給需要使用的使用者。
4. 確認 Budget Admission 和相關存取政策已生效。

### 1.5 提供 Token Resolver

Codex 透過 Token Resolver 取得 Entra Access Token，並使用 Bearer Token 向 APIM 發送請求。

本專案提供 `scripts/codex-token-resolver/install.ps1`。管理員或使用者先開啟此檔案，將頂端參數改成目標環境的公開連線資料；Installer 之後會安裝 Microsoft MSAL Resolver、以 Windows DPAPI 保護 Token Cache、設定使用者環境變數，並更新 Codex 設定檔。

**管理員交付內容**

- 此 repository 或組織核准的 installer 套件。
- 目標環境的 Tenant、Client、Audience、Scope、Gateway URL、Model Alias 與 Provider ID。
- 以下單一安裝／登入命令。

Resolver 應區分兩種操作：

| 操作 | 用途 |
|---|---|
| Login / Check | 供使用者互動登入，並顯示非敏感的 Token Claims |
| Token Resolution | 供 Codex 自動呼叫，取得有效的 Bearer Token |

Codex 使用的 Token Resolution Command 必須將純 Access Token 輸出至標準輸出（stdout），且不得混入診斷文字。這是 Codex 讀取 Token 的介面要求；Token 不應出現在使用者可見的診斷輸出、Log 或 Repository 中。

### 1.6 管理員交付檢查

開放使用者連接前，應完成：

- [ ] 共用 Employee Public Client App Registration 已取得 `Model.Invoke` Delegated Permission。
- [ ] Entra Admin Consent 已完成。
- [ ] Codex Token Resolver 與 APIM Policy 使用相同的共用 `employeeClientId`。
- [ ] 模型已發布，且 Model Route 可正常使用。
- [ ] 使用者已取得對應模型的指派權限。
- [ ] Budget Admission 設定正確。
- [ ] Token Resolver 已完成封裝與驗證。
- [ ] 已提供使用者安裝方式、登入命令及 Codex 設定參數。

---

## Part 2. 使用者設定（Windows Setup）

本節適用於已取得 Turnstile 使用權限的 Windows 使用者。

完成以下步驟，即可透過 Codex CLI 或支援自訂 Provider 的 Codex Desktop 用戶端使用 Turnstile Gateway。

### 2.1 一鍵安裝與登入

從 repository root 開啟 installer，修改檔案頂端的 `TenantId`、`ClientId`、`Audience`、`Scope`、`GatewayBaseUrl`、`Model`、`ProviderId` 與 `ProviderName`，然後執行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\codex-token-resolver\install.ps1 `
	-Login
```

Installer 會自動完成：

- 安裝 Resolver 與 npm 依賴到 `%USERPROFILE%\.codex\turnstile-auth`；
- 永久設定目前 Windows 使用者的 `TURNSTILE_*` 環境變數，並依 tenant/client 隔離 Token Cache；
- 更新 `%USERPROFILE%\.codex\config.toml`；
- 啟動 Microsoft device-code 登入並檢查 claims。

依照終端顯示的 Microsoft 登入網址及一次性驗證碼完成登入。

成功後，驗證資訊應符合：

```text
azp = be989933-a2eb-42ef-9ae6-72024b01a997
aud = 7398a26d-832a-4a9d-889f-04b3c74218c4
scp = Model.Invoke
tid = b9bbf971-ad4d-4759-acf5-93dc3599c3f6
```

若驗證結果不符，請確認 Codex Token Resolver 使用的是 `employeeClientId` 對應的共用 App Registration，而非 Azure CLI 的 Client ID；Claude Code 使用同一個 Client ID 是預期行為。

> 不要複製其他使用者的 Token Cache，或將 Access Token 手動寫入設定檔。

### 2.2 確認 Codex 設定

Installer 會更新 Codex 使用者層級設定檔：

```text
%USERPROFILE%\.codex\config.toml
```

需要檢查時可執行：

```powershell
notepad "$HOME\.codex\config.toml"
```

不需要手動加入設定。Installer 會寫入目前環境的 model、provider、Gateway URL 與 Resolver 絕對路徑，並保留其他既有設定。

產生的設定包含：

```toml
model = "gpt-5.6-luna-foundry-6e35e30c"
model_provider = "turnstile"

[model_providers.turnstile]
name = "Turnstile APIM"
base_url = "https://kurt-apim.azure-api.net/vicadopted/llm"
wire_api = "responses"

[model_providers.turnstile.auth]
command = 'C:\Program Files\nodejs\node.exe'
args = ['C:\Users\<user>\.codex\turnstile-auth\token.cjs']
timeout_ms = 15000
refresh_interval_ms = 300000
```

**設定說明**

| 參數 | 說明 |
|---|---|
| `model` | Turnstile 已發布且使用者有權限的模型 Alias |
| `model_provider` | Provider ID，與下方 Table 名稱一致 |
| `base_url` | Gateway API Endpoint |
| `wire_api` | 使用 OpenAI Responses API |
| `auth.command` | Token Resolver 的執行命令 |
| `auth.args` | 管理員指定的 Token 取得參數 |
| `timeout_ms` | Resolver 最長執行時間（15 秒） |
| `refresh_interval_ms` | Codex 重新取得 Token 的間隔（5 分鐘） |

實際路徑由 Installer 依目前電腦產生；`config.toml` 不會儲存 Access Token。

### 2.3 驗證 Codex CLI 連線

完成設定後，開啟 PowerShell，執行：

```powershell
codex doctor --summary --ascii
```

確認 Codex 環境與 Provider Endpoint 沒有連線錯誤。

接著執行實際模型請求：

```powershell
codex exec --model "gpt-5.6-luna-foundry-6e35e30c" --sandbox read-only "Reply with exactly: gateway-ok"
```

成功時，模型應回覆：

```text
gateway-ok
```

執行資訊也應顯示使用自訂 Provider：

```text
provider: turnstile
```

`codex doctor` 主要用於環境診斷；只有實際模型請求成功，才能確認 Token、APIM Route 與模型權限皆可正常使用。

### 2.4 設定 ChatGPT Desktop（Codex 模式）

若使用的 Windows Desktop 版本支援讀取 Codex 的自訂 Provider 設定：

1. 完全關閉 ChatGPT Desktop。
2. 確認 `config.toml` 已完成設定。
3. 重新啟動 ChatGPT Desktop。
4. 進入 **Codex → New chat**。
5. 使用 `gpt-5.6-luna-foundry-6e35e30c` 模型。
6. 發送以下測試訊息：

```text
Reply with exactly: gateway-ok
```

若收到 `gateway-ok`，代表本次模型請求已成功完成。

若模型沒有出現在選單中，請先透過 Codex CLI 驗證自訂 Provider，再確認目前 Desktop 版本的自訂模型或 Model Catalog 支援情況。

### 2.5 常見問題

**Q1. 出現 `403 model_not_assigned`**

代表 Turnstile 模型授權拒絕目前使用者的存取。

**處理方式：** 請聯繫 Turnstile Owner，確認是否已被指派：

`gpt-5.6-luna-foundry-6e35e30c`

不需要重新建立 App Registration，也不要嘗試關閉模型指派機制。

**Q2. 出現 `401 Unauthorized` 或 `invalid token`**

通常與 Access Token 無效、過期或 Token Claims 不符有關。

請重新執行管理員提供的 Resolver Check 指令，確認：

- `azp` 為 Codex Client ID。
- `aud` 為 Gateway API。
- `scp` 包含 `Model.Invoke`。
- `tid` 為指定的 Tenant ID。

必要時依管理員提供的方式重新登入。

**Q3. `/models` 回傳 `404 Not Found`**

Codex 可能嘗試查詢：

```text
https://kurt-apim.azure-api.net/vicadopted/llm/models
```

目前 Turnstile 的模型相容端點位於 `/v1/models`，且回傳固定的空模型清單。

因此 `/models` 的 404 警告不一定代表 OAuth 或推論服務失敗。

請以實際 `/responses` 推論請求是否成功作為主要驗證依據。模型 Alias 應由管理員提供，必要時透過 Codex Model Catalog 明確配置。

**Q4. 修改設定後仍使用原本的 Provider**

請確認：

1. 修改的是使用者層級的 `%USERPROFILE%\.codex\config.toml`。
2. `model_provider = "turnstile"` 位於頂層。
3. `[model_providers.turnstile]` 的名稱完全一致。
4. 沒有其他設定或啟動參數覆蓋 Provider。
5. 已完全重新啟動相關應用程式。

**Q5. Codex 設定是否會影響 Claude？**

不會直接影響。

Codex 與 Claude 使用獨立的 App Registration、Client ID 與 Token Cache，但可以共用相同的 Turnstile Gateway API。

如遇 Claude 連線異常，請由管理員確認 APIM Policy 是否同時保留兩個 Client ID。

### 2.6 安全注意事項

- 不要將 `auth.json`、MSAL Token Cache 或其他認證檔案提交至 Git。
- 不要在 Issue、文件或聊天紀錄中貼出 Access Token、Refresh Token、Client Secret 或 APIM Subscription Key。
- 不要自行複製其他使用者的登入資訊。
- Token Resolver 應使用組織核准的安裝方式及安全儲存機制。
- 若需要調整 Gateway、Model Alias 或模型權限，請聯繫 Turnstile 管理員。

**完成以上步驟後，即可透過 Turnstile APIM 使用已授權的模型，而不需要直接管理模型服務的 API Key。**