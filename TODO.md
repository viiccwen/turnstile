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

- **企業目錄仍為 Mock**：Organization、Department、Project、Agent 與 20 個 Person 仍是 Contoso 固定資料，尚無 CRUD 或 Entra Directory 同步。
- **Application 歸屬未完成**：自 APIM 匯入的 Application 沒有 Owner／Department；新建項目仍不設定 Department，成本無法完整歸屬。
- **Budget 功能未完整**：目前只有 Token Budget／Admission，尚無 USD Budget／Admission。
- **Model Intelligent Router 未開發**：目前只有 APIM failover／balanced／weighted pool，沒有依 Prompt、成本或模型能力自動選模。
- **GitHub Copilot 尚未 Production-ready**：功能已接線，但用量、成本與治理資料仍需真實組織的端對端驗證。
- **仍有硬編碼資料**：Runtime Health Check 固定寫入 Contoso 歸屬資訊，且前端會將 legacy `user-XX` 改寫為測試信箱。
- **Live E2E 尚未完成**：Clean-clone 自助部署、APIM 升級／回滾、圖片生成及 PostgreSQL／Table Storage／Event Hub／Log Analytics，目前主要只有 Mock／Fixture 測試。
- **FinOps Assistant 尚待驗證**：工具查詢已實作，但最終文字與圖表中的數字尚未逐項確認皆來自工具結果。
- **部署彈性已完成實機驗收**：Managed／Adopted 的部署、健康、登入、ownership、真實模型 publication、BFF→APIM 推論、Event Hub persisted telemetry 與安全清理均通過；最終 validation resources／APIM children 為 0，Live Health 為 HTTP 200。
