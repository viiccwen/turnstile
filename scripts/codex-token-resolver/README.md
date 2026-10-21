# Turnstile Codex Token Resolver

此目錄包含 Codex custom provider 使用的 Windows Token Resolver

## 設定環境

先開啟編輯 `installer.ps1`：

修改檔案頂端的環境參數：

```powershell
[string]$TenantId = '<tenant-id>'
[string]$ClientId = '<employee-client-id>'
[string]$Audience = '<gateway-api-client-id>'
[string]$Scope = 'api://<gateway-api-client-id>/Model.Invoke'
[string]$GatewayBaseUrl = 'https://<gateway-host>/<api-path>'
[string]$Model = '<published-model-alias>'
[string]$ProviderId = '<codex-provider-id>'
[string]$ProviderName = '<provider-display-name>'
```

## 使用者安裝

需求：Node.js 18 以上、PowerShell，以及此 repository。

從 repository root 執行一個指令：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\codex-token-resolver\install.ps1 `
	-Login
```

Installer 會自動安裝和設定，根據指示啟動 Microsoft device-code 登入並檢查

完成 Microsoft 登入後，重新啟動 Codex CLI 或 ChatGPT Desktop 即可

## 疑難排解

- `Missing resolver configuration`：確認 `install.ps1` 頂端的環境參數已填妥，再重新執行 installer 並重新啟動 Codex。
- `Run the resolver with --login`：重新執行 `install.ps1 -Login`。
- Claims 不符：確認 tenant、audience、scope 與共用 Employee App Registration 的 `employeeClientId`。
- `403 model_not_assigned`：驗證已成功；Turnstile Owner 必須將已發布模型指派給使用者。
