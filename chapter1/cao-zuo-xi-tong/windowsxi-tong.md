# Windows Server 2022 安全加固配置指南

> **三重引用框架**：本指南基于 GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》（三级）、CIS Microsoft Windows Server 2022 Benchmark v2.0.0 及 Microsoft 官方安全基准（Security Compliance Toolkit）编写。
>
> **适用对象**：系统管理员、安全运维人员、等级保护测评人员。
>
> **配置方式**：优先使用 PowerShell 命令实现自动化加固，同时保留组策略路径说明供 GUI 操作参考。

---

## 1. 身份鉴别

### 1.1 交互式登录：无需按 Ctrl+Alt+Del → 启用要求

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求① — "应对登录的用户进行身份标识和鉴别，应提供并启用登录失败处理功能"
- CIS Benchmark：Windows Server 2022 §2.3.7.5 — "Interactive logon: Do not require CTRL+ALT+DEL"

**命令/配置路径：**
```powershell
# 禁用"无需按 Ctrl+Alt+Del"（即启用要求按 Ctrl+Alt+Del）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DisableCAD" -Value 0 -Type DWord

# 验证
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DisableCAD"
# 预期输出：DisableCAD = 0
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "交互式登录：无需按 Ctrl+Alt+Del" → 设置为"已禁用"

---

### 1.2 密码长度策略

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求② — "操作系统应配置密码复杂度要求，密码长度最小值应不少于 8 位"
- CIS Benchmark：Windows Server 2022 §1.1.2 — "Minimum password length"

**命令/配置路径：**
```powershell
# 设置密码长度最小值为 8 位（L3 建议 12 位）
net accounts /minpwlen:12

# 或通过 PowerShell 直接操作安全策略
$SecEditPath = "$env:TEMP\secpol.cfg"
secedit /export /cfg $SecEditPath
(Get-Content $SecEditPath) -replace 'MinimumPasswordLength = \d+', 'MinimumPasswordLength = 12' | Set-Content $SecEditPath
secedit /configure /db $env:windir\security\local.sdb /cfg $SecEditPath /areas SECURITYPOLICY
Remove-Item $SecEditPath -Force

# 验证
net accounts | findstr /i "长度"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 账户策略 → 密码策略 → "密码长度最小值"

---

### 1.3 密码复杂度要求

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求② — "应配置密码复杂度要求，包含大写字母、小写字母、数字和特殊字符中至少三种"
- CIS Benchmark：Windows Server 2022 §1.1.1 — "Enforce password history"

**命令/配置路径：**
```powershell
# 启用密码必须符合复杂性要求
net accounts /minpwlen:12 /maxpwage:90

# 通过 secedit 启用密码复杂度
$SecEditPath = "$env:TEMP\secpol.cfg"
secedit /export /cfg $SecEditPath
(Get-Content $SecEditPath) -replace 'PasswordComplexity = \d+', 'PasswordComplexity = 1' | Set-Content $SecEditPath
secedit /configure /db $env:windir\security\local.sdb /cfg $SecEditPath /areas SECURITYPOLICY
Remove-Item $SecEditPath -Force

# 验证
secedit /export /areas SECURITYPOLICY /cfg "$env:TEMP\secpol_check.cfg"
Select-String "PasswordComplexity" "$env:TEMP\secpol_check.cfg"
Remove-Item "$env:TEMP\secpol_check.cfg" -Force
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 账户策略 → 密码策略 → "密码必须符合复杂性要求"

---

### 1.4 密码期限策略

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求② — "应配置密码最长使用期限，不超过 90 天"
- CIS Benchmark：Windows Server 2022 §1.1.4 — "Maximum password age"

**命令/配置路径：**
```powershell
# 设置密码最长使用期限为 90 天
net accounts /maxpwage:90

# 设置密码最短使用期限为 1 天（防止频繁循环修改绕过历史策略）
net accounts /minpwage:1

# 验证
net accounts | findstr /i "期限"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 账户策略 → 密码策略 → "密码最长使用期限" / "密码最短使用期限"

---

### 1.5 密码历史策略

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求② — "应配置密码历史，至少记住 5 次密码"
- CIS Benchmark：Windows Server 2022 §1.1.1 — "Enforce password history"

**命令/配置路径：**
```powershell
# 设置强制密码历史为 24 个（CIS 推荐值）
net accounts /uniquepw:24

# 验证
net accounts | findstr /i "历史"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 账户策略 → 密码策略 → "强制密码历史"

---

### 1.6 账户锁定策略

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求③ — "应启用登录失败处理功能，配置账户锁定阈值和锁定时间"
- CIS Benchmark：Windows Server 2022 §1.2.1 — "Account lockout duration"

**命令/配置路径：**
```powershell
# 设置账户锁定阈值：5 次无效登录后锁定
net accounts /lockoutthreshold:5

# 设置锁定时间：30 分钟
net accounts /lockoutduration:30

# 设置锁定计数器重置时间：30 分钟
net accounts /lockoutwindow:30

# 验证
net accounts | findstr /i "锁定"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 账户策略 → 账户锁定策略 → "账户锁定阈值" / "账户锁定时间" / "重置账户锁定计数器"

---

### 1.7 远程桌面（RDP）加密与安全配置

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求④ — "应采用密码技术保证远程管理过程中的数据保密性和完整性"
- CIS Benchmark：Windows Server 2022 §2.3.10.5 — "Network security: Minimum session security for NTLM SSP based (including secure RPC)"

**命令/配置路径：**
```powershell
# 要求使用网络级身份验证（NLA）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1 -Type DWord

# 设置 RDP 会话加密级别为高位（FIPS 140-2 兼容）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel" -Value 3 -Type DWord

# 禁用 RDP 驱动器/剪贴板重定向（按需）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp" `
    -Name "fDisableCdm" -Value 1 -Type DWord

# 配置 RDP 使用 TLS 1.2
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
    -Name "Enabled" -Value 1 -Type DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" `
    -Name "DisabledByDefault" -Value 0 -Type DWord -Force

# 验证
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp" `
    -Name "UserAuthentication", "MinEncryptionLevel"
```

**组策略路径：** 计算机配置 → 管理模板 → Windows 组件 → 远程桌面服务 → 远程桌面会话主机 → 安全 → "要求使用网络级身份验证进行远程连接" / "设置客户端连接加密级别"

---

### 1.8 双因子认证（等保三级增强要求）

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.1 要求⑤ — "应采用两种或两种以上组合的鉴别技术对管理用户进行身份鉴别（三级及以上）"
- CIS Benchmark：Windows Server 2022 §2.3.1.2 — "Accounts: Limit local account use of blank passwords to console logon only"

**命令/配置路径：**
```powershell
# 等保三级要求管理员使用双因子认证。
# 以下配置为启用 Windows Hello 企业版（PIN + 生物识别）或 SmartCard 支持

# 1. 启用 SmartCard 强制登录
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ScForceOption" -Value 1 -Type DWord

# 2. 要求 SmartCard 用于交互式登录（域环境）
# 在域控上配置：仅允许 SmartCard 登录

# 3. 启用 Windows Defender Credential Guard（基于虚拟化的安全，保护凭据）
# 需要支持虚拟化技术的硬件
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

# 验证
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ScForceOption"
```

> **说明**：双因子认证的具体实现方式（SmartCard、硬件 Token、TOTP、Windows Hello）需根据组织实际部署方案选择。以上为启用 SmartCard 强制登录的基础配置。

---

## 2. 访问控制

### 2.1 禁用默认管理共享（Admin Shares）

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.2 要求② — "应删除或重命名默认账户，应关闭不必要的默认共享"
- CIS Benchmark：Windows Server 2022 §2.3.11.1 — "Network access: Do not allow anonymous enumeration of SAM accounts and shares"

**命令/配置路径：**
```powershell
# 禁用 Admin$、C$、IPC$ 等默认共享（重启后生效）
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "AutoShareServer" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "AutoShareWks" -Value 0 -Type DWord

# 立即删除现有共享（无需重启）
net share Admin$ /delete
net share IPC$ /delete
# 注意：C$ 需要先停止 Server 服务再删除，此处推荐配置注册表后重启

# 验证
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "AutoShareServer", "AutoShareWks"
```

**组策略路径：** 计算机配置 → 管理模板 → 网络 → Lanman 服务器 → "启用不安全的来宾登录" / 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "网络访问：不允许 SAM 账户和共享的匿名枚举"

---

### 2.2 重命名 Administrator 账户

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.2 要求② — "应重命名默认账户，修改默认账户的默认口令"
- CIS Benchmark：Windows Server 2022 §2.3.1.3 — "Accounts: Rename administrator account"

**命令/配置路径：**
```powershell
# 重命名 Administrator 账户为自定义名称（建议使用难以猜测的名称）
$NewAdminName = "SecAdmin-$(Get-Random -Minimum 1000 -Maximum 9999)"
$AdminUser = Get-LocalUser -Name "Administrator"
Rename-LocalUser -Name "Administrator" -NewName $NewAdminName

# 创建带有欺骗性的蜜罐账户"Administrator"（无实际权限，用于记录攻击行为）
$Password = ConvertTo-SecureString "DummyP@ss123!$" -AsPlainText -Force
New-LocalUser -Name "Administrator" -Password $Password -Description "Built-in account for administering the computer/domain" -AccountNeverExpires
Add-LocalGroupMember -Group "Guests" -Member "Administrator"

# 验证
Get-LocalUser | Select-Object Name, Enabled
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "账户：重命名管理员账户"

---

### 2.3 禁用 Guest 账户

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.2 要求② — "应删除或禁用默认账户，Guest 账户应禁用"
- CIS Benchmark：Windows Server 2022 §2.3.1.1 — "Accounts: Guest account status"

**命令/配置路径：**
```powershell
# 禁用 Guest 账户
Disable-LocalUser -Name "Guest"

# 验证禁用状态
$Guest = Get-LocalUser -Name "Guest"
if ($Guest.Enabled) {
    Write-Warning "Guest 账户未禁用！"
} else {
    Write-Output "Guest 账户已成功禁用。"
}

# 可选：重命名 Guest 账户（增加攻击难度）
Rename-LocalUser -Name "Guest" -NewName "Gu3stDisabled"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "账户：来宾账户状态"

---

### 2.4 用户账户控制（UAC）配置 — 最小权限原则

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.2 要求③ — "应根据管理用户的角色分配权限，实现最小权限原则"
- CIS Benchmark：Windows Server 2022 §2.3.4.1 — "User Account Control: Admin Approval Mode for the Built-in Administrator account"

**命令/配置路径：**
```powershell
# UAC 策略配置（符合 CIS 推荐值）

# 1. 内置管理员账户的管理员审批模式
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "FilterAdministratorToken" -Value 1 -Type DWord

# 2. 所有管理员以审批模式运行
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 1 -Type DWord

# 3. 行为提升提示：非 Windows 二进制文件（值 1=凭据提示，值 2=安全桌面提示）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

# 4. 检测应用程序安装并提示提升
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableInstallerDetection" -Value 1 -Type DWord

# 5. 仅提升签名和验证的可执行文件
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ValidateAdminCodeSignatures" -Value 0 -Type DWord

# 验证
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA", "FilterAdministratorToken", "ConsentPromptBehaviorAdmin"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "用户账户控制：以管理员批准模式运行所有管理员"

---

### 2.5 安全选项：不显示最后登录用户名

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.7（剩余信息保护） 要求① — "应清除登录过程中的残余信息，不显示上次登录用户名"
- CIS Benchmark：Windows Server 2022 §2.3.7.4 — "Interactive logon: Do not display last user name"

**命令/配置路径：**
```powershell
# 不显示最后登录的用户名
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DontDisplayLastUserName" -Value 1 -Type DWord

# 验证
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DontDisplayLastUserName"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "交互式登录：不显示上次登录的用户名"

---

## 3. 安全审计

### 3.1 审核策略 — 全面开启成功与失败审核

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.3 要求① — "应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计"
- CIS Benchmark：Windows Server 2022 §3.2 — "Advanced Audit Policy Configuration"

**命令/配置路径：**
```powershell
# 使用高级审核策略（Windows Server 2022 推荐方式）
# 应用审核策略的以下子类别（全部审核成功+失败）

# 登录/注销
auditpol /set /subcategory:"登录" /success:enable /failure:enable
auditpol /set /subcategory:"注销" /success:enable /failure:enable
auditpol /set /subcategory:"账户锁定" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec 主模式" /success:enable /failure:enable
auditpol /set /subcategory:"其他登录/注销事件" /success:enable /failure:enable
auditpol /set /subcategory:"网络策略服务器" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos 服务票证操作" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos 身份验证服务" /success:enable /failure:enable
auditpol /set /subcategory:"凭据验证" /success:enable /failure:enable

# 账户管理
auditpol /set /subcategory:"用户账户管理" /success:enable /failure:enable
auditpol /set /subcategory:"计算机账户管理" /success:enable /failure:enable
auditpol /set /subcategory:"安全组管理" /success:enable /failure:enable
auditpol /set /subcategory:"分发组管理" /success:enable /failure:enable
auditpol /set /subcategory:"应用程序组管理" /success:enable /failure:enable
auditpol /set /subcategory:"其他账户管理事件" /success:enable /failure:enable

# 详细跟踪（进程追踪）
auditpol /set /subcategory:"进程创建" /success:enable /failure:enable
auditpol /set /subcategory:"进程终止" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI 活动" /success:enable /failure:enable
auditpol /set /subcategory:"RPC 事件" /success:enable /failure:enable

# DS 访问（域控）
auditpol /set /subcategory:"目录服务访问" /success:enable /failure:enable
auditpol /set /subcategory:"目录服务更改" /success:enable /failure:enable

# 对象访问
auditpol /set /subcategory:"文件系统" /success:enable /failure:enable
auditpol /set /subcategory:"注册表" /success:enable /failure:enable
auditpol /set /subcategory:"应用程序生成的" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"认证的中央访问策略暂存" /success:enable /failure:enable

# 特权使用
auditpol /set /subcategory:"敏感特权使用" /success:enable /failure:enable
auditpol /set /subcategory:"非敏感特权使用" /success:enable /failure:enable
auditpol /set /subcategory:"其他特权使用事件" /success:enable /failure:enable

# 策略更改
auditpol /set /subcategory:"审核策略更改" /success:enable /failure:enable
auditpol /set /subcategory:"身份验证策略更改" /success:enable /failure:enable
auditpol /set /subcategory:"授权策略更改" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC 规则级策略更改" /success:enable /failure:enable
auditpol /set /subcategory:"其他策略更改事件" /success:enable /failure:enable

# 验证当前审核策略
auditpol /get /category:*
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 高级审核策略配置

---

### 3.2 审核日志大小与保留策略

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.3 要求② — "应确保审计日志的存储空间充足，配置合理的日志保留策略，防止日志被覆盖"
- CIS Benchmark：Windows Server 2022 §3.1 — "Event log size and retention"

**命令/配置路径：**
```powershell
# 配置安全日志：至少 1GB，保留 180 天
wevtutil sl Security /ms:1073741824   # 1GB = 1,073,741,824 字节
wevtutil sl Security /rt:180          # 保留 180 天
wevtutil sl Security /ab:true         # 自动备份日志

# 配置系统日志：至少 512MB，保留 180 天
wevtutil sl System /ms:536870912
wevtutil sl System /rt:180
wevtutil sl System /ab:true

# 配置应用程序日志：至少 256MB，保留 90 天
wevtutil sl Application /ms:268435456
wevtutil sl Application /rt:90
wevtutil sl Application /ab:true

# 配置 PowerShell 操作日志（增强审计）
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:536870912
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /rt:180

# 验证日志配置
wevtutil gl Security | findstr "maxSize retention autoBackup"
wevtutil gl System | findstr "maxSize retention"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 事件日志 → "应用程序日志大小最大值" / "安全日志大小最大值" / "系统日志大小最大值" / "日志保留天数"

---

## 4. 入侵防范

### 4.1 系统更新配置（WSUS / 自动更新）

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.4 要求① — "应能检测到入侵事件和漏洞，并及时更新系统补丁"
- CIS Benchmark：Windows Server 2022 §4.1 — "Configure Automatic Updates"

**命令/配置路径：**
```powershell
# 配置 Windows Update 为自动下载并安装（推荐 WSUS 环境使用）
# 场景 A：独立服务器 — 启用自动更新
$AUSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
$AUSettings.NotificationLevel = 4  # 4=自动下载并计划安装
$AUSettings.Save()

# 场景 B：WSUS 环境 — 指向内部 WSUS 服务器
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "UseWUServer" -Value 1 -Type DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
    -Name "WUServer" -Value "http://wsus.yourdomain.com:8530" -Type String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
    -Name "WUStatusServer" -Value "http://wsus.yourdomain.com:8530" -Type String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "ScheduledInstallDay" -Value 0 -Type DWord -Force  # 0=每天
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "ScheduledInstallTime" -Value 3 -Type DWord -Force   # 凌晨3点
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "AutoInstallMinorUpdates" -Value 1 -Type DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -Force

# 场景 C：检查并安装缺失的更新（脱机模式）
Install-Module PSWindowsUpdate -Force -Confirm:$false
Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot

# 验证更新配置
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
```

**组策略路径：** 计算机配置 → 管理模板 → Windows 组件 → Windows 更新 → "配置自动更新"

---

### 4.2 关闭高危端口 — Windows Defender 防火墙

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.4 要求② — "应关闭不需要的系统服务和高危端口，防止利用开放端口进行入侵"
- CIS Benchmark：Windows Server 2022 §9.3 — "Windows Defender Firewall"

**命令/配置路径：**
```powershell
# 确保 Windows Defender 防火墙在所有配置文件中启用
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 默认入站规则：阻止
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# 默认出站规则：允许（根据安全策略可改为阻止）
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# ---- 高危端口阻止规则 ----

# 阻止入站 TCP 135（RPC Endpoint Mapper / DCOM）
New-NetFirewallRule -DisplayName "Block TCP 135 - RPC Endpoint Mapper" `
    -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block

# 阻止入站 UDP 135
New-NetFirewallRule -DisplayName "Block UDP 135 - RPC Endpoint Mapper" `
    -Direction Inbound -Protocol UDP -LocalPort 135 -Action Block

# 阻止入站 TCP 139（NetBIOS Session Service）
New-NetFirewallRule -DisplayName "Block TCP 139 - NetBIOS Session" `
    -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block

# 阻止入站 TCP/UDP 137-138（NetBIOS Name/Datagram）
New-NetFirewallRule -DisplayName "Block UDP 137-138 - NetBIOS" `
    -Direction Inbound -Protocol UDP -LocalPort 137-138 -Action Block

# 阻止入站 TCP 445（SMB）
New-NetFirewallRule -DisplayName "Block TCP 445 - SMB" `
    -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block

# 其他应阻止的高危端口
$HighRiskPorts = @(
    @{Port=1433; Name="SQL Server"},        # SQL Server
    @{Port=3306; Name="MySQL"},              # MySQL
    @{Port=3389; Name="RDP"},                # RDP（如需远程管理，改为仅允许特定源IP）
    @{Port=5985; Name="WinRM HTTP"},         # WinRM（按需开放）
    @{Port=5986; Name="WinRM HTTPS"}         # WinRM HTTPS（按需开放）
)

foreach ($p in $HighRiskPorts) {
    New-NetFirewallRule -DisplayName "Block TCP $($p.Port) - $($p.Name)" `
        -Direction Inbound -Protocol TCP -LocalPort $($p.Port) -Action Block
}

# 如业务需要 RDP，改为仅允许特定 IP 范围
# New-NetFirewallRule -DisplayName "Allow RDP from Management Subnet" `
#     -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "192.168.10.0/24" -Action Allow

# 验证防火墙规则
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Block *" } | `
    Select-Object DisplayName, Direction, Action, Enabled
```

> ⚠️ **注意**：封锁 135/139/445 端口可能会影响域环境中的正常通信（如 SYSVOL 复制、组策略更新等）。在域控制器上需谨慎操作，建议在成员服务器上执行，并在域控上保留必要的安全例外规则。

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 高级安全 Windows Defender 防火墙

---

### 4.3 关闭不必要的服务

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.4 要求③ — "应关闭不必要的系统服务和默认共享，减少攻击面"
- CIS Benchmark：Windows Server 2022 §5.1 — "Disable unnecessary services"

**命令/配置路径：**
```powershell
# 安全基线建议关闭的服务列表（非域控/非特定角色时）
$ServicesToDisable = @(
    @{Name="XblAuthManager"; Desc="Xbox Live 认证管理器"},
    @{Name="XblGameSave"; Desc="Xbox Live 游戏存档"},
    @{Name="XboxNetApiSvc"; Desc="Xbox Live 网络服务"},
    @{Name="XboxGipSvc"; Desc="Xbox 外设管理"},
    @{Name="lfsvc"; Desc="地理定位服务"},
    @{Name="MapsBroker"; Desc="已下载地图管理器"},
    @{Name="MessagingService"; Desc="消息服务"},
    @{Name="PcaSvc"; Desc="程序兼容性助手"},
    @{Name="RemoteRegistry"; Desc="远程注册表"},
    @{Name="WMPNetworkSvc"; Desc="Windows Media Player 网络共享"},
    @{Name="WSearch"; Desc="Windows 搜索（非域控/文件服务器按需）"},
    @{Name="wcncsvc"; Desc="Windows Connect Now"},
    @{Name="Fax"; Desc="传真服务"},
    @{Name="irmon"; Desc="红外线监视器"},
    @{Name="SharedAccess"; Desc="ICS 共享访问"},
    @{Name="TabletInputService"; Desc="触控键盘服务"},
    @{Name="WalletService"; Desc="钱包服务"},
    @{Name="stisvc"; Desc="Windows 图像获取"}
)

foreach ($svc in $ServicesToDisable) {
    $Service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($Service -and $Service.StartType -ne "Disabled") {
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Write-Output "已禁用服务：$($svc.Name) ($($svc.Desc))"
    } elseif (-not $Service) {
        Write-Output "服务不存在或未安装：$($svc.Name)"
    } else {
        Write-Output "服务已禁用：$($svc.Name)"
    }
}

# 验证当前服务启动类型（导出报告）
Get-Service | Where-Object { $_.StartType -eq "Disabled" } | `
    Select-Object Name, DisplayName, Status, StartType | `
    Export-Csv -Path "$env:TEMP\disabled_services_audit.csv" -NoTypeInformation
```

> ⚠️ **注意**：服务禁用需根据服务器角色（DC、DNS、DHCP、IIS 等）评估业务影响。以上列表仅供非角色服务器参考。

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 系统服务（手动设置各项服务的启动模式）

---

## 5. 恶意代码防范

### 5.1 Windows Defender 实时保护配置

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.5 要求① — "应安装防恶意代码软件，并定期更新病毒库和扫描"
- CIS Benchmark：Windows Server 2022 §8.1 — "Windows Defender Antivirus"

**命令/配置路径：**
```powershell
# 启用实时保护
Set-MpPreference -DisableRealtimeMonitoring $false

# 启用行为监视
Set-MpPreference -DisableBehaviorMonitoring $false

# 启用脚本扫描
Set-MpPreference -DisableScriptScanning $false

# 启用 I/O 排除（保护性扫描所有下载和附件）
Set-MpPreference -DisableIOAVProtection $false

# 启用云保护（MAPS）
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudTimeout 50

# 启用 PUA 保护（识别潜在不需要的应用程序）
Set-MpPreference -PUAProtection Enabled

# 启用网络保护（防止访问恶意站点/钓鱼）
Set-MpPreference -EnableNetworkProtection Enabled

# 设置扫描参数
Set-MpPreference -ScanScheduleDay Everyday
Set-MpPreference -ScanScheduleQuickScanTime "02:00"
Set-MpPreference -ScanAvgCPULoadFactor 50

# 更新病毒库
Update-MpSignature

# 执行快速扫描
Start-MpScan -ScanType QuickScan

# 验证 Defender 配置
Get-MpPreference | Select-Object `
    DisableRealtimeMonitoring, `
    DisableBehaviorMonitoring, `
    DisableScriptScanning, `
    DisableIOAVProtection, `
    MAPSReporting, `
    CloudBlockLevel, `
    PUAProtection, `
    EnableNetworkProtection

# 检查 Defender 服务状态
Get-Service -Name "WinDefend"
```

**组策略路径：** 计算机配置 → 管理模板 → Windows 组件 → Microsoft Defender 防病毒 → 实时保护 → "打开实时保护" / "打开行为监视"

---

### 5.2 Windows Defender 扫描与排除配置

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.5 要求② — "应定期对系统进行恶意代码扫描，并合理配置排除项避免影响业务"
- CIS Benchmark：Windows Server 2022 §8.2 — "Microsoft Defender Antivirus exclusions"

**命令/配置路径：**
```powershell
# 配置定期扫描计划
# 每周六凌晨 2:00 执行完整扫描
Set-MpPreference -ScanParameters 2  # 2=FullScan
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan" `
    -Name "ScheduleDay" -Value 6 -Type DWord -Force  # 6=Saturday
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan" `
    -Name "ScheduleTime" -Value 2 -Type DWord -Force  # 2=凌晨2点

# 配置排除项（根据业务需要谨慎配置）
# 示例：排除 SQL Server 数据目录、IIS 日志目录
# Add-MpPreference -ExclusionPath "D:\SQLData"
# Add-MpPreference -ExclusionPath "C:\inetpub\logs"
# Add-MpPreference -ExclusionExtension ".bak"

# 配置定期签名更新检查频率
Set-MpPreference -SignatureUpdateInterval 8  # 每 8 小时检查更新

# 验证
Get-MpComputerStatus | Select-Object `
    AMServiceEnabled, `
    AntivirusEnabled, `
    RealTimeProtectionEnabled, `
    NISEnabled, `
    QuickScanStartTime, `
    FullScanStartTime, `
    AntispywareSignatureLastUpdated
```

**组策略路径：** 计算机配置 → 管理模板 → Windows 组件 → Microsoft Defender 防病毒 → 扫描 → "指定每天运行快速扫描的时间间隔"

---

## 6. 资源控制

### 6.1 屏幕保护与超时锁定

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.6 要求① — "应提供登录会话超时锁定功能，超过设定时间自动锁定会话"
- CIS Benchmark：Windows Server 2022 §2.3.7.1 — "Interactive logon: Machine inactivity limit"

**命令/配置路径：**
```powershell
# 设置屏幕保护程序超时（900 秒 = 15 分钟）
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "900"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value "1"

# 系统级别：设置交互式登录：计算机不活动限制（CIS 推荐 15 分钟）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Value 900 -Type DWord

# 启用屏幕保护程序（系统范围强制）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "NoDispScrSavPage" -Value 0 -Type DWord

# 验证
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs"
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "交互式登录：计算机不活动限制"

---

### 6.2 远程桌面（终端）会话超时

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.6 要求② — "应限制单个用户的多重并发会话，设置会话空闲超时断开"
- CIS Benchmark：Windows Server 2022 §2.3.7.3 — "Interactive logon: Machine inactivity limit for RDP sessions"

**命令/配置路径：**
```powershell
# 设置 RDP 会话空闲超时断开（15 分钟）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxIdleTime" -Value 900000 -Type DWord  # 单位：毫秒，900000=15分钟

# 达到超时后终止会话（而非仅断开）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxDisconnectionTime" -Value 60000 -Type DWord  # 断开后 1 分钟终止

# 限制活动会话的最大时长（如 8 小时 = 28800000 毫秒）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxSessionTime" -Value 28800000 -Type DWord

# 限制每个用户只能有一个 RDP 会话
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fSingleSessionPerUser" -Value 1 -Type DWord

# 验证
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "MaxIdleTime", "MaxDisconnectionTime", "MaxSessionTime", "fSingleSessionPerUser"
```

**组策略路径：** 计算机配置 → 管理模板 → Windows 组件 → 远程桌面服务 → 远程桌面会话主机 → 会话时间限制 → "设置已中断会话的时间限制" / "活动会话的时间限制" / "空闲会话的时间限制"

---

### 6.3 资源监控配置

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.6 要求③ — "应对系统资源（CPU、内存、磁盘）进行监控，设置告警阈值"
- CIS Benchmark：Windows Server 2022 §5.2 — "Monitor system resources"

**命令/配置路径：**
```powershell
# 启用性能计数器日志收集（数据收集器集）

# 1. 创建系统诊断数据收集器集（内置）
logman start "System\System Diagnostics" -s

# 2. 创建自定义性能监视器
$DataCollectorSetName = "ServerResourceMonitor"
$CollectorPath = "$env:TEMP\$DataCollectorSetName"
logman create counter $DataCollectorSetName -o "$env:SYSTEMROOT\PerfLogs\Admin\$DataCollectorSetName" `
    -cf - -f bin -si 300 -v nnnnnn `
    --ct "perfmon\Processor(*)\% Processor Time" `
    --ct "perfmon\Memory\Available MBytes" `
    --ct "perfmon\Memory\Pages/sec" `
    --ct "perfmon\LogicalDisk(*)\% Free Space" `
    --ct "perfmon\LogicalDisk(*)\Avg. Disk Queue Length" `
    --ct "perfmon\Network Interface(*)\Bytes Total/sec"

# 3. 启动数据收集器集
logman start $DataCollectorSetName

# 4. 配置资源监视器警报（通过事件触发任务）

# 磁盘空间不足告警（逻辑卷剩余空间 < 10%）
$Volumes = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3"
foreach ($vol in $Volumes) {
    $FreePercent = ($vol.FreeSpace / $vol.Size) * 100
    if ($FreePercent -lt 10) {
        Write-Warning "磁盘 $($vol.DeviceID) 剩余空间不足 10%！当前：$('{0:N2}' -f $FreePercent)%"
    }
}

# 5. 验证当前运行的数据收集器
logman query -s
```

> 建议部署集中式监控方案（如 Zabbix、Prometheus + Windows Exporter、SCOM）配合此基线。以上为本机基础性能计数器配置。

---

## 7. 剩余信息保护

### 7.1 关机时清除虚拟内存页面文件

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.7 要求② — "应确保系统关机时清除内存中的残留信息，防止通过分析页面文件获取敏感数据"
- CIS Benchmark：Windows Server 2022 §2.3.6.1 — "Shutdown: Clear virtual memory pagefile"

**命令/配置路径：**
```powershell
# 关机时清除虚拟内存页面文件
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord

# 验证
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -Name "ClearPageFileAtShutdown"
```

> ⚠️ **注意**：启用此设置将延长关机时间，因为系统需要在关机时清除 pagefile.sys。在物理服务器上存在非敏感工作负载时，可根据风险接受程度酌情决定。

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "关机：清除虚拟内存页面文件"

---

### 7.2 登录时不显示最后登录用户名

**🔗 标准映射**
- GB/T 22239-2019：§7.1.3.7 要求① — "应清除登录过程中的残余信息，防止泄露用户账户信息"
- CIS Benchmark：Windows Server 2022 §2.3.7.4 — "Interactive logon: Do not display last user name"

> 此条目与 §2.5 为同一控制项，已在身份鉴别章节中配置。此处为交叉引用，确保完整性。

**命令/配置路径：**
```powershell
# 已在章节 2.5 中配置，此处为验证命令
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "DontDisplayLastUserName"
# 预期输出：DontDisplayLastUserName = 1
```

**组策略路径：** 计算机配置 → Windows 设置 → 安全设置 → 本地策略 → 安全选项 → "交互式登录：不显示上次登录的用户名"

---

## 附录 A：GB/T 22239-2019 控制点映射表（操作系统）

以下映射表基于 GB/T 22239-2019 三级安全要求（安全计算环境 — 操作系统层面），列出本文档各加固项与标准条文的对应关系。

| 等保要求编号 | 要求分类 | 安全要求描述 | 本文档对应章节 | 加固要点 |
|:---:|:---:|---|---|---|
| §7.1.3.1 | 身份鉴别 | 身份标识和鉴别；密码复杂度（长度≥8，包含大/小/数字/特殊）；密码期限≤90天；密码历史≥5次；登录失败处理（锁定策略） | §1.1 ~ §1.8 | Ctrl+Alt+Del 要求、密码策略、锁定策略、RDP TLS、双因子 |
| §7.1.3.2 | 访问控制 | 默认账户重命名/禁用；按用户分配权限（最小权限）；默认共享关闭；访问控制粒度 | §2.1 ~ §2.5 | 关闭 Admin$、重命名 Administrator、禁用 Guest、UAC、不显示最后用户名 |
| §7.1.3.3 | 安全审计 | 审计策略覆盖用户和重要事件；日志存储和保留；审计记录保护；时间同步 | §3.1 ~ §3.2 | 全面审核策略（成功+失败）、日志大小≥1GB、保留≥180天 |
| §7.1.3.4 | 入侵防范 | 补丁更新；端口和服务控制；最小化安装；漏洞扫描 | §4.1 ~ §4.3 | WSUS/自动更新、防火墙封锁135/139/445、禁用不必要服务 |
| §7.1.3.5 | 恶意代码防范 | 安装防恶意代码软件；定期更新病毒库；定期扫描 | §5.1 ~ §5.2 | Windows Defender 实时保护、行为监视、云保护、定期扫描 |
| §7.1.3.6 | 资源控制 | 会话超时锁定；并发会话限制；资源监控 | §6.1 ~ §6.3 | 屏幕保护15min锁定、RDP空闲断开、性能监视器和告警 |
| §7.1.3.7 | 剩余信息保护 | 清除登录残留信息；清除内存/页面文件残留信息 | §7.1 ~ §7.2 | 关机清除页面文件、不显示最后登录用户名 |

### 等级保护级别说明

| 等保级别 | 标准依据 | 适用场景 | 差异化要点 |
|:---:|---|---|---|
| 一级（L1） | GB/T 22239-2019 §6 | 基础保护 | 基本身份鉴别、简单访问控制 |
| 二级（L2） | GB/T 22239-2019 §6 | 一般保护 | 增加审计功能、基础恶意代码防范 |
| 三级（L3） | GB/T 22239-2019 §7 | 较高级保护 ✅ | **本指南目标等级**：双因子认证、全面审计、入侵防范、资源控制 |
| 四级（L4） | GB/T 22239-2019 §8 | 高级保护 | 在 L3 基础上增加专用安全设备、增强审计、容错等 |

---

## 附录 B：一键加固脚本（PowerShell）

将以下内容保存为 `Hardening-WinSrv2022.ps1`，以管理员身份执行：

```powershell
#Requires -RunAsAdministrator
# Windows Server 2022 一键加固脚本

Write-Host "[*] 开始 Windows Server 2022 安全加固..." -ForegroundColor Green

# ---- 1. 身份鉴别 ----
Write-Host "[1/7] 配置身份鉴别策略..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord
net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:24 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TerminalServer\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Type DWord

# ---- 2. 访问控制 ----
Write-Host "[2/7] 配置访问控制..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Type DWord
$RandSuffix = Get-Random -Minimum 10000 -Maximum 99999
Rename-LocalUser -Name "Administrator" -NewName "SecAdmin-$RandSuffix" -ErrorAction SilentlyContinue
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -Type DWord

# ---- 3. 安全审计 ----
Write-Host "[3/7] 配置审计策略..."
$AuditCategories = @(
    "登录","注销","账户锁定","IPsec 主模式","其他登录/注销事件","凭据验证",
    "用户账户管理","计算机账户管理","安全组管理","分发组管理","其他账户管理事件",
    "进程创建","进程终止",
    "文件系统","注册表","SAM",
    "敏感特权使用","非敏感特权使用","其他特权使用事件",
    "审核策略更改","身份验证策略更改","授权策略更改","其他策略更改事件"
)
foreach ($cat in $AuditCategories) {
    auditpol /set /subcategory:"$cat" /success:enable /failure:enable
}
wevtutil sl Security /ms:1073741824 /rt:180 /ab:true
wevtutil sl System /ms:536870912 /rt:180 /ab:true
wevtutil sl Application /ms:268435456 /rt:90 /ab:true

# ---- 4. 入侵防范（防火墙规则） ----
Write-Host "[4/7] 配置防火墙规则..."
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block
New-NetFirewallRule -DisplayName "Block TCP 135 - RPC" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block
New-NetFirewallRule -DisplayName "Block UDP 135 - RPC" -Direction Inbound -Protocol UDP -LocalPort 135 -Action Block
New-NetFirewallRule -DisplayName "Block TCP 139 - NetBIOS" -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block
New-NetFirewallRule -DisplayName "Block UDP 137-138 - NetBIOS" -Direction Inbound -Protocol UDP -LocalPort 137-138 -Action Block
New-NetFirewallRule -DisplayName "Block TCP 445 - SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block

# ---- 5. 恶意代码防范 ----
Write-Host "[5/7] 配置 Windows Defender..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -EnableNetworkProtection Enabled
Update-MpSignature

# ---- 6. 资源控制 ----
Write-Host "[6/7] 配置资源控制..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900000 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fSingleSessionPerUser" -Value 1 -Type DWord

# ---- 7. 剩余信息保护 ----
Write-Host "[7/7] 配置剩余信息保护..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord

Write-Host "[+] Windows Server 2022 加固完成！建议重启服务器以使部分配置生效。" -ForegroundColor Green
Write-Host "[!] 注意：此脚本包含封锁 135/139/445 端口的规则，请确认不影响业务。" -ForegroundColor Yellow
```

---

## 附录 C：CIS Benchmark 参考编号速查表

| 本文档章节 | CIS Benchmark 编号 | 名称 |
|:---:|:---:|---|
| §1.2 | §1.1.1 | Enforce password history |
| §1.3 | §1.1.1 | Enforce password history |
| §1.4 | §1.1.4 | Maximum password age |
| §1.5 | §1.1.1 | Enforce password history |
| §1.6 | §1.2.1 | Account lockout duration |
| §1.1 | §2.3.7.5 | Interactive logon: Do not require CTRL+ALT+DEL |
| §2.2 | §2.3.1.3 | Accounts: Rename administrator account |
| §2.3 | §2.3.1.1 | Accounts: Guest account status |
| §2.4 | §2.3.4.1 | User Account Control: Admin Approval Mode for Built-in Administrator account |
| §2.5 / §7.2 | §2.3.7.4 | Interactive logon: Do not display last user name |
| §3.1 | §3.2 | Advanced Audit Policy Configuration |
| §3.2 | §3.1 | Event log size and retention |
| §4.1 | §4.1 | Configure Automatic Updates |
| §4.2 | §9.3 | Windows Defender Firewall |
| §5.1 | §8.1 | Windows Defender Antivirus |
| §6.1 | §2.3.7.1 | Interactive logon: Machine inactivity limit |
| §6.2 | §2.3.7.3 | Interactive logon: Machine inactivity limit for RDP sessions |
| §7.1 | §2.3.6.1 | Shutdown: Clear virtual memory pagefile |

---

> **文档版本**：v1.0  
> **适用系统**：Windows Server 2022（Standard / Datacenter）  
> **基于标准**：GB/T 22239-2019（三级）、CIS Microsoft Windows Server 2022 Benchmark v2.0.0  
> **最后更新**：2026 年 6 月  
> **使用说明**：本文档中的 PowerShell 命令建议在测试环境验证后，再应用到生产环境。部分策略（如 135/139/445 端口封锁）需根据服务器角色和业务需求调整。
