# 2026/09/16 TODO

1. 確認是否可以使用已存在 / 特定的 resource group / resource, 以及如何使用

可重用的既有資源：Resource Group, Storage Account, APIM, Foundry

2. 部署需要哪些權限

- Subscription：`Reader`，且 Resource Provider 與目標 Resource Group 已由管理員建立。
- Platform Resource Group：`Contributor` + `User Access Administrator`。
- APIM：`API Management Service Contributor`，限該 APIM Service。
- Storage：`Storage Blob Data Contributor` + `Storage Table Data Contributor`
- Entra App Registration：Tenant 允許使用者建立 App。
- Foundry：APIM Managed Identity 需有 `Cognitive Services User`。
- 部署者在 Storage／Foundry Scope 需具 `Role Based Access Control Administrator`。

3. 要能夠指定現有 VNet, resource

> 程式已支援指定既有 Resource Group，並採用既有 Storage、APIM、Foundry、VNet／Subnet、PostgreSQL／Key Vault、Event Hub 及 Log Analytics／Application Insights；Managed／Adopted 隔離環境已完成實機驗收。

建議驗證架構：

- **不要切換現有環境的 Ownership**：保留目前參數與 deployment state，另建 validation Resource Group、`resourcePrefix`、Storage containers／ledger table 與 APIM child IDs。
- **Managed baseline**：先讓 validation 環境自行建立 VNet、PostgreSQL、Event Hub、監控及 Key Vault，保存完整驗收結果後移除。
- **Adopted path**：在獨立 dependency Resource Group 預先建立 VNet 與四個專用 Subnet、PostgreSQL Database／Key Vault secrets、專用 Event Hub，以及同一 Workspace 下的 Application Insights，再由第二個 validation 環境全部採用。
- **目前 VNet 若要重用**：不要共用四個 live Subnet；可在 `10.42.0.0/16` 內另切兩個 Flex `/27`、一個 API `/27` 與一個 Private Endpoint `/24`，並沿用已連結的 Key Vault Private DNS Zone。
- **目前 PostgreSQL 為 Stopped**：若要採用現有 Server，先啟動並建立獨立 Database；較安全作法仍是使用專用驗證 Server／Database，避免測試 migration 或負載碰觸 live 資料。
- **通過條件**：兩條路徑的業務驗收結果一致；What-if 為 0 Delete；重跑為冪等；Remove dry-run 將所有 adopted resource 列為 protected，實際清理後外部依賴仍存在。

4. 測試 Claude Code

> 目前無法

5. 部署 Single Sign-on

> 已完成, 但發現使用 LLM quota 前 Budget Management 不會出現該帳號, 研究後發現 Entra 首次登入建立的是 member, Budget Management 顯示的是 Owner, Members 需要等 Gateway 流量提供有效部門歸屬後才會出現

# 2026/09/17 TODO

1. 盤點哪些功能尚未開發 / Mock

- **企業目錄仍為 Mock**：Organization、Department、Project、Agent 與 20 個 Person 仍是 Contoso 固定資料，尚無 CRUD 或 Entra Directory 同步；**Entra ID 使用者不會在首次登入後立即出現在 Budget 管控畫面**：使用者必須先產生具有有效部門歸屬的 Gateway 流量，系統才會將其納入 Budget Management。
- **Application 歸屬未完成**：自 APIM 匯入的 Application 沒有 Owner／Department；新建項目仍不設定 Department，成本無法完整歸屬。
- **Budget 功能未完整**：目前只有 Token Budget／Admission，尚無 USD Budget／Admission。
- **尚無 Model Intelligent Router**：目前只有 APIM failover／balanced／weighted pool，沒有依 Prompt、成本或模型能力自動選模，但在會議中有看到，所以是還沒推上開源版。
- **GitHub Copilot 尚未 Production-ready**：功能已接線，但用量、成本與治理資料仍需真實組織的端對端驗證。
- **FinOps Assistant 尚待驗證**：工具查詢已實作，但最終文字與圖表中的數字尚未逐項確認皆來自工具結果。

# 2026/09/23 TODO

1. owner 只能使用帳密設定嘛?
2. managedmentApiKey 是甚麼
3. 補上那些參數要去哪裡取得

# 2026/10/02 TODO

1. 為何要在參數綁定 Foundry? 只能指定一個 Foundry?
2. Fernet Key 如何產生?
3. credential 每個都要講清楚如何填寫
4. 申請 app registration (entra client ID), 要如何設定 / permission?
5. Subnet 可以填一樣的嗎? 或是限制?
6. 建置好後哪些設定

# 2026/10/07 TODO

1. `credentialEncryptionKey` 補上定義，產生的連結網址
2. `managementApiKey` 補上定義，產生的連結網址
3. `apimSubscriptionKey` 補上定義，產生的連結網址
4. "若要依部門歸屬 telemetry，可新增 department-* App Roles，例如 department-platform，再於 Enterprise applications 將 users/groups 指派至該 role。這些 roles 是選填。" -> 移除他

# 2026/10/21 TODO

## 討論內容
1. Turnstile v1.2 更新
2. GitHub Copilot Changelog (近三個月)
3. 下個月的 AI credit

## pre

1. organization, department 仍是 Mock data
2. Member 仍未解決完整的成員歸戶管理: Entra ID 使用者不會在首次登入後立即出現在 Budget 管控畫面：使用者必須先打過帶有部門的 request，系統才會偵測到並將其納入 Budget Management
3. Model Intelligent Router 不包含在 v1.2
4. 新增 APIM, self-hosted Gateway 管理頁面
5. Foundry 現在不需放入平台部署公開參數檔 (Sync 後會 migrate 這部分)
7. 新增 Atomic 美元預算與成本 (Sync 後會 migrate 這部分)
8. 加上模型價格管理預填入 (GPT 5.6+ 相關模型皆不支援)
9. 多 APIM 模型發布 (目前僅支援 API, UI 尚未支援)


## Notes

組織部門:
1. add user by Entra
2. import group 時是否會帶 user list
3. 確認如何取得模型價格
4. * 目前若透過 Azure Portal 手動修改 Policy、權限，或部分 Gateway 未同步更新，可能導致平台顯示的設定與實際執行狀態不一致 -> 證實
5. 哪些問題在 v1.2 已經被解決了

6. 查一下 Copilot CLI limits soft-cap