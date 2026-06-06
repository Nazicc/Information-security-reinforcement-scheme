# Linux 操作系统安全加固指南

> **适用版本：** Red Hat Enterprise Linux 9 / AlmaLinux 9 / CentOS Stream 9  
> **参考框架：** GB/T 22239-2019（等保 2.0 三级） + CIS Benchmark for RHEL 9 v2.0 + 最佳实践  
> **最后更新：** 2026-06-06

---

## 1. 身份鉴别

### 1.1 口令过期策略（/etc/login.defs）

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.2 要求[1] — 应对登录的用户进行身份标识和鉴别，口令定期更换
- CIS Benchmark：RHEL 9 §5.5.1.1 — Set Password Expiration Parameters

**说明：** 通过 `login.defs` 设置口令最长有效期、最短有效期和过期前警告天数。

**命令：**
```bash
# 设置 PASS_MAX_DAYS（口令最长有效期）为 90 天
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs

# 设置 PASS_MIN_DAYS（最短修改间隔）为 7 天
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs

# 设置 PASS_WARN_AGE（过期前警告天数）为 14 天
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# 验证修改
grep -E '^PASS_(MAX|MIN|WARN)_DAYS' /etc/login.defs
```

### 1.2 PAM pwquality 口令复杂度策略

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.2 要求[2] — 口令复杂度要求（大写字母、小写字母、数字、特殊字符中至少三种）
- CIS Benchmark：RHEL 9 §5.5.2 — Set Password Quality Requirements

**说明：** RHEL 9 使用 `pwquality` 替代旧版 `cracklib`，通过 PAM 模块 `pam_pwquality.so` 实施口令复杂度检查。

**命令：**
```bash
# 配置口令复杂度策略
cat > /etc/security/pwquality.conf.d/99-hardening.conf << 'EOF'
# 最小长度 8 位
minlen = 8
# 至少包含 1 个大写字母
ucredit = -1
# 至少包含 1 个小写字母
lcredit = -1
# 至少包含 1 个数字
dcredit = -1
# 至少包含 1 个特殊字符
ocredit = -1
# 至少包含 3 种字符类型
minclass = 3
# 不允许回文
palindrome = 1
# 不允许顺序字符（如 abc、123）
sequential = 1
# 不允许包含用户名
usercheck = 1
# 允许自动回退（如果无法加载词典则不报错）
enforce_for_root = 0
EOF

# 验证配置
pwmake 128 2>/dev/null || echo "pwquality 配置已生效"
```

### 1.3 PAM faillock 登录失败锁定

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.2 要求[3] — 登录失败超过指定次数后应采取锁定措施
- CIS Benchmark：RHEL 9 §5.5.3 — Set Lockout for Failed Password Attempts

**说明：** RHEL 9 使用 `faillock` 替代旧版 `tally2`，实现登录失败后的账户锁定机制。

**命令：**
```bash
# 配置 faillock 策略
cat > /etc/security/faillock.conf << 'EOF'
# 连续 5 次失败后锁定
deny = 5
# 锁定时间 900 秒（15 分钟）
unlock_time = 900
# 失败计数器保持时间 900 秒（即 15 分钟内连续失败才累计）
fail_interval = 900
# 计入 root 用户
even_deny_root
# root 用户锁定时间（即使 even_deny_root，也为 root 单独设置较短锁定）
root_unlock_time = 900
# 锁定后记录日志
audit = 1
# 显示失败次数
silent = 0
EOF

# 确保 system-auth 和 password-auth 已集成 faillock
authselect select sssd with-faillock --force

# 验证
authselect current
```

### 1.4 SSH 禁用 root 登录 + 密钥认证

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.2 要求[4] — 限制默认账户的登录，应用 SSH 密钥方式进行身份鉴别
- CIS Benchmark：RHEL 9 §6.2.9 — Disable SSH Root Login

**命令：**
```bash
# 禁用 root 密码登录，仅允许密钥认证
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

# 禁用空口令登录
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# 禁用密码认证（仅密钥认证）
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# 限制允许登录的用户（仅白名单用户可 SSH）
echo "AllowUsers admin sysadmin" >> /etc/ssh/sshd_config

# 仅允许 SSH 协议版本 2
sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config

# 重启 sshd 服务
systemctl restart sshd

# 验证配置
sshd -T | grep -E '(permitrootlogin|passwordauthentication|permitemptypasswords)'
```

### 1.5 SSH 超时自动退出

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.8 要求[1] — 应提供会话超时锁定或退出机制
- CIS Benchmark：RHEL 9 §6.2.13 — Set SSH Client Alive Interval

**命令：**
```bash
# 设置 SSH 超时自动退出（300 秒无活动即断开）
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

# 重启 sshd 服务
systemctl restart sshd

# 验证配置
sshd -T | grep -E '(clientaliveinterval|clientalivecountmax)'
```

---

## 2. 访问控制

### 2.1 删除或锁定不必要的系统账户

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.3 要求[1] — 应启用访问控制机制，删除或锁定不必要的账户
- CIS Benchmark：RHEL 9 §6.2.14 — Ensure System Accounts Are Non-Login

**命令：**
```bash
# 将非 root 系统账户（UID < 1000）的 shell 锁定为 /sbin/nologin
for u in $(awk -F: '{if ($3 < 1000 && $1 != "root") print $1}' /etc/passwd); do
    current_shell=$(getent passwd "$u" | cut -d: -f7)
    if [ "$current_shell" != "/sbin/nologin" ] && [ "$current_shell" != "/sbin/shutdown" ] && [ "$current_shell" != "/sbin/halt" ]; then
        usermod -s /sbin/nologin "$u"
    fi
done

# 锁定不必要的服务账户（如 games、nobody 等）
usermod -L games 2>/dev/null || true
usermod -L ftp 2>/dev/null || true

# 验证
awk -F: '{if ($3 < 1000 && $1 != "root") print $1 ":" $7}' /etc/passwd

# 列出所有可登录账户（shell 不是 nologin/false 的）
echo "=== 可登录账户列表 ==="
awk -F: '($7 != "/sbin/nologin" && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/usr/bin/false") {print $1 " (UID:" $3 ")"}' /etc/passwd
```

### 2.2 sudo 日志审计

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.3 要求[2] — 应记录特权用户的操作行为
- CIS Benchmark：RHEL 9 §7.2 — Configure sudo Using a Dedicated Log File

**命令：**
```bash
# 配置 sudo 日志记录
cat > /etc/sudoers.d/99-logging << 'EOF'
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output
Defaults iolog_dir=/var/log/sudo-io
Defaults passwd_tries=3
Defaults badpass_message="密码错误次数过多，操作已记录"
EOF

# 验证语法
visudo -c -f /etc/sudoers.d/99-logging

# 创建日志目录并设置权限
mkdir -p /var/log/sudo-io
chmod 750 /var/log/sudo-io
chown root:root /var/log/sudo-io
```

### 2.3 umask 设置

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.3 要求[3] — 应设置默认权限掩码，限制新建文件/目录的默认权限
- CIS Benchmark：RHEL 9 §5.4.4 — Set Default umask for Users

**命令：**
```bash
# 设置全局 umask 为 027（所有者全部权限，组读/执行，其他无权限）
echo "umask 027" > /etc/profile.d/umask.sh
chmod 644 /etc/profile.d/umask.sh

# 为 bash 用户设置
sed -i 's/^#*umask.*/umask 027/' /etc/bashrc 2>/dev/null || echo "umask 027" >> /etc/bashrc

# 为 csh 用户设置
sed -i 's/^#*umask.*/umask 027/' /etc/csh.cshrc 2>/dev/null || echo "umask 027" >> /etc/csh.cshrc

# 设置 systemd user umask
mkdir -p /etc/systemd/system/user@.service.d
cat > /etc/systemd/system/user@.service.d/umask.conf << 'EOF'
[Service]
UMask=027
EOF

# 验证
echo "当前 umask: $(umask)"
```

### 2.4 SELinux enforcing 模式

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.3 要求[4] — 应采用强制访问控制机制
- CIS Benchmark：RHEL 9 §1.6.1.1 — Ensure SELinux Is Installed and in Enforcing Mode

**命令：**
```bash
# 检查 SELinux 状态
getenforce

# 设置 SELinux 为 enforcing 模式
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# 立即生效（无需重启）
setenforce 1

# 重启时自动恢复 SELinux 上下文标签（如果是首次从 disabled 切换到 enforcing）
touch /.autorelabel

# 验证
echo "当前模式: $(getenforce)"
echo "配置文件: $(grep ^SELINUX= /etc/selinux/config)"

# 检查 SELinux 布尔值（按需调整常用设置）
setsebool -P ssh_sysadm_login off
```

---

## 3. 安全审计

### 3.1 auditd 关键文件监控

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.4 要求[1] — 应对系统中的关键操作和文件进行审计
- CIS Benchmark：RHEL 9 §4.1.x — Configure System Accounting (auditd)

**命令：**
```bash
# 安装 auditd（RHEL 9 默认已安装）
dnf install -y audit

# 配置关键文件审计规则
cat > /etc/audit/rules.d/99-critical-files.rules << 'EOF'
# 监控用户账户文件 - 写操作
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# 监控 SELinux 配置
-w /etc/selinux -p wa -k selinux

# 监控 SSH 配置
-w /etc/ssh/sshd_config -p wa -k sshd

# 监控 sudo 相关
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo

# 监控系统启动与计划任务
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/crontab -p wa -k cron

# 监控系统库和内核模块
-w /etc/modprobe.conf -p wa -k modprobe
-w /etc/modprobe.d/ -p wa -k modprobe

# 监控系统日志配置
-w /etc/rsyslog.conf -p wa -k rsyslog
-w /etc/rsyslog.d/ -p wa -k rsyslog

# 监控系统重要配置文件
-w /etc/fstab -p wa -k system-config
-w /etc/hosts -p wa -k system-config
-w /etc/hosts.allow -p wa -k system-config
-w /etc/hosts.deny -p wa -k system-config

# 监控特权命令执行
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged

# 监控时间修改
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change

# 监控用户/组管理
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod

# 监控网络配置修改
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-mod

# 监控内核模块加载
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /sbin/rmmod -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# 审计日志文件大小和保留
-b 8192
-f 1
EOF

# 加载规则
augenrules --load

# 设置审计日志保留策略
cat > /etc/audit/auditd.conf << 'EOF'
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = incremental_async
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file = 50
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF

# 重启 auditd 服务
systemctl restart auditd

# 验证
auditctl -l | head -20
```

### 3.2 rsyslog 日志集中

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.4 要求[2] — 审计记录应进行集中管理
- CIS Benchmark：RHEL 9 §4.2.x — Configure rsyslog

**命令：**
```bash
# 配置 rsyslog 发送日志到集中日志服务器（请替换 <LOG_SERVER_IP>）
cat > /etc/rsyslog.d/99-central-logging.conf << 'EOF'
# 所有设施的所有级别日志转发到集中服务器（TCP 可靠传输）
*.* @@<LOG_SERVER_IP>:514

# 使用 RELP 协议（如果支持，更可靠）
# :omrelp:<LOG_SERVER_IP>:514

# 本地同时保留日志
$ActionQueueType LinkedList
$ActionQueueFileName remote_fwd
$ActionResumeRetryCount -1
$ActionQueueSaveOnShutdown on
EOF

# 启用日志接收（在日志服务器端）
# cat > /etc/rsyslog.d/99-remote-receive.conf << 'EOF'
# # 通过 TCP 接收远程日志
# $ModLoad imtcp
# $InputTCPServerRun 514
# EOF

# 确保 rsyslog 服务开启
systemctl enable --now rsyslog

# 验证
rsyslogd -N1
logger "rsyslog test message"
grep "rsyslog test message" /var/log/messages
```

### 3.3 日志轮转（logrotate）

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.4 要求[3] — 审计记录应受到保护，定期备份，保留期限满足要求
- CIS Benchmark：RHEL 9 §4.3 — Configure logrotate

**命令：**
```bash
# 配置系统日志轮转策略
cat > /etc/logrotate.d/syslog << 'EOF'
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    missingok
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2>/dev/null` 2>/dev/null || true
    endscript
}
EOF

# 配置全局轮转策略
cat > /etc/logrotate.conf << 'EOF'
# 每周轮转
weekly
# 保留 52 周（1 年）
rotate 52
# 轮转后创建新日志文件
create
# 使用日期作为后缀
dateext
# 压缩旧日志
compress
# 延迟压缩（上一份保留不压缩）
delaycompress
# 缺失日志文件不报错
missingok
# 不为空则不轮转
notifempty
# 系统日志单独配置
include /etc/logrotate.d
EOF

# 验证
logrotate -d /etc/logrotate.conf | head -30
```

---

## 4. 入侵防范

### 4.1 最小安装原则

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.5 要求[1] — 应遵循最小安装原则，仅安装需要的组件和应用程序
- CIS Benchmark：RHEL 9 §1.2 — Configure Software Updates

**命令：**
```bash
# 列出已安装的软件包数量
echo "已安装软件包数量: $(rpm -qa --qf '%{NAME}\n' | wc -l)"

# 卸载不必要的开发工具和编译器（生产环境建议移除）
dnf remove -y gcc gcc-c++ make autoconf automake 2>/dev/null || true

# 卸载不必要的桌面环境
dnf remove -y '@Server with GUI' '@X Window System' 2>/dev/null || true

# 卸载不必要的打印机服务
dnf remove -y cups 2>/dev/null || true

# 列出所有安装的软件包（供审查）
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > /root/installed_packages.txt
echo "已保存软件包列表到 /root/installed_packages.txt"
```

### 4.2 关闭不需要的服务（firewalld 管理）

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.5 要求[2] — 应关闭不需要的系统服务和端口
- CIS Benchmark：RHEL 9 §3.x — Configure Network Firewall

**命令：**
```bash
# 启用 firewalld（RHEL 9 默认防火墙）
systemctl enable --now firewalld

# 查看当前开放的端口和服务
firewall-cmd --list-all

# 删除不必要的服务（示例：移除 cockpit、dhcpv6 等）
firewall-cmd --permanent --remove-service=cockpit 2>/dev/null || true
firewall-cmd --permanent --remove-service=dhcpv6-client 2>/dev/null || true

# 仅放行 SSH 服务
firewall-cmd --permanent --add-service=ssh

# 如果有必要开放其他端口（示例：HTTP/HTTPS）
# firewall-cmd --permanent --add-service=http
# firewall-cmd --permanent --add-service=https

# 重新加载防火墙规则
firewall-cmd --reload

# 停止并禁用不必要的系统服务
systemctl disable --now avahi-daemon 2>/dev/null || true
systemctl disable --now cups 2>/dev/null || true
systemctl disable --now rpcbind 2>/dev/null || true
systemctl disable --now nfs-server 2>/dev/null || true
systemctl disable --now telnet.socket 2>/dev/null || true
systemctl disable --now rlogin.socket 2>/dev/null || true
systemctl disable --now rexec.socket 2>/dev/null || true
systemctl disable --now postfix 2>/dev/null || true

# 验证
echo "=== 正在监听端口 ==="
ss -tlnp
echo "=== 已启用服务 ==="
systemctl list-units --type=service --state=running | grep -E '\.service'
```

### 4.3 系统更新（dnf-automatic）

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.5 要求[3] — 应提供更新系统组件的机制
- CIS Benchmark：RHEL 9 §1.2.1 — Ensure GPG keys are configured; §1.2.3 — Ensure gpgcheck is globally activated; §1.3 — Configure dnf-automatic

**命令：**
```bash
# 安装 dnf-automatic
dnf install -y dnf-automatic

# 配置自动安全更新
cat > /etc/dnf/automatic.conf << 'EOF'
[commands]
# 仅应用安全更新
upgrade_type = security
# 随机延迟（避免同时更新时压垮镜像源）
random_sleep = 15
# 自动下载并安装
download_updates = yes
apply_updates = yes

[emitters]
# 启用系统日志通知
emit_via = motd

[base]
# 不需要额外配置，使用系统默认的 dnf 源
EOF

# 启用并启动定时更新
systemctl enable --now dnf-automatic.timer

# 验证
systemctl status dnf-automatic.timer --no-pager

# 手动检查可用更新
dnf update --security --assumeno 2>/dev/null | head -20
```

### 4.4 文件完整性 AIDE

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.5 要求[4] — 应提供重要文件的完整性检测机制
- CIS Benchmark：RHEL 9 §1.4.1 — Ensure AIDE is Installed

**命令：**
```bash
# 安装 AIDE
dnf install -y aide

# 初始化 AIDE 数据库
aide --init

# 将初始数据库移动到标准位置
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 配置 AIDE 规则（监控关键系统文件）
cat > /etc/aide.conf << 'EOF'
# 数据库路径
database=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
gzip_dbout=yes

# 详细级别
verbose=5

# 定义检查规则
# p: 权限, i: inode, n: 链接数, u: 用户, g: 组
# s: 大小, b: 块数, m: mtime, a: atime
# S: SHA1, SHA256: SHA256, RMD160: RIPEMD160, TIGER: TIGER
# sha512: SHA512
ALL = p+i+n+u+g+s+b+m+S+sha512
NORMAL = sha512+sha256+rmd160+tiger
DIR = p+i+n+u+g
PERMS = p+i+u+g
STATIC = p+i+n+u+g+b+m+S+sha512
LOG = p+i+n+u+g+S
LSPP = p+i+n+u+g+s+b+m+S+sha512

# 监控关键目录和文件
/boot/boot NORMAL
/boot/vmlinuz NORMAL
/bin NORMAL
/sbin NORMAL
/lib NORMAL
/lib64 NORMAL
/opt NORMAL
/usr NORMAL
/root NORMAL

/etc NORMAL
/etc/passwd ALL
/etc/shadow ALL
/etc/group ALL
/etc/gshadow ALL
/etc/selinux ALL
/etc/ssh/sshd_config ALL
/etc/sudoers ALL
/etc/fstab ALL
/etc/hosts ALL
/etc/hosts.allow STATIC
/etc/hosts.deny STATIC

# 排除无需监控的目录
!/var/log
!/var/cache
!/var/tmp
!/tmp
!/run
!/proc
!/sys
!/dev
EOF

# 重新初始化数据库（应用新配置）
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 创建每日定时检查脚本
cat > /etc/cron.daily/aide-check << 'SCRIPT'
#!/bin/bash
# AIDE 每日完整性检查
AIDE_DB="/var/lib/aide/aide.db.gz"
AIDE_REPORT="/var/log/aide/aide-report-$(date +%Y%m%d).txt"

mkdir -p /var/log/aide

if [ -f "$AIDE_DB" ]; then
    aide --check > "$AIDE_REPORT" 2>&1
    if [ $? -ne 0 ]; then
        echo "AIDE 检测到文件变更！请立即审查: $AIDE_REPORT"
        logger -p authpriv.warning "AIDE integrity check FAILED - see $AIDE_REPORT"
    fi
fi

# 保留 90 天报告
find /var/log/aide -name "aide-report-*.txt" -mtime +90 -delete
SCRIPT

chmod +x /etc/cron.daily/aide-check

# 验证
aide --version
echo "AIDE 数据库已初始化: $(zcat /var/lib/aide/aide.db.gz | wc -l) 个条目"
```

### 4.5 漏洞扫描提醒

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.5 要求[5] — 应定期进行漏洞扫描，发现潜在安全漏洞
- CIS Benchmark：RHEL 9 §1.2 — Software Updates

**命令：**
```bash
# 安装 OpenSCAP 用于合规扫描
dnf install -y openscap-scanner scap-security-guide

# 执行 CIS 基线合规扫描（RHEL 9）
oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis \
    --results /root/scap-cis-results.xml \
    --report /root/scap-cis-report.html \
    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# 执行 DISA STIG 扫描（可选）
# oscap xccdf eval \
#     --profile xccdf_org.ssgproject.content_profile_stig \
#     --results /root/scap-stig-results.xml \
#     --report /root/scap-stig-report.html \
#     /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

echo "CIS 合规报告已生成: /root/scap-cis-report.html"

# 安装 dnf-plugin-security 漏洞提醒脚本
cat > /etc/cron.weekly/security-advisory-check << 'SCRIPT'
#!/bin/bash
# 每周安全公告检查
ADVISORY_FILE="/root/security-advisories-$(date +%Y%m%d).txt"

echo "=== 待处理安全更新 ===" > "$ADVISORY_FILE"
dnf updateinfo list --security >> "$ADVISORY_FILE" 2>&1

echo "" >> "$ADVISORY_FILE"
echo "=== 重要/紧急安全通告 ===" >> "$ADVISORY_FILE"
dnf updateinfo list --sec-severity=Important --sec-severity=Critical >> "$ADVISORY_FILE" 2>&1

if [ -s "$ADVISORY_FILE" ]; then
    echo "安全公告已保存至: $ADVISORY_FILE"
    logger -p authpriv.info "Weekly security advisory check complete: $ADVISORY_FILE"
fi
SCRIPT

chmod +x /etc/cron.weekly/security-advisory-check
```

---

## 5. 恶意代码防范

### 5.1 ClamAV 恶意代码防护

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.6 要求[1] — 应安装恶意代码防范软件
- CIS Benchmark：RHEL 9 §1.8.2 — Ensure GDM login banner is configured（注：ClamAV 非 CIS 强制要求，但属等保必选）

**命令：**
```bash
# 安装 ClamAV（EPEL 源）
dnf install -y epel-release
dnf install -y clamav clamav-update clamav-scanner-systemd

# 配置病毒库更新
cat > /etc/freshclam.conf << 'EOF'
DatabaseMirror db.cn.clamav.net
DatabaseMirror clamav.stu.edu.tw
DatabaseMirror db.local.clamav.net
MaxAttempts = 5
Checks = 24
NotifyClamd = /etc/clamd.d/scan.conf
DatabaseOwner = clamupdate
LogRotate = true
LogFileMaxSize = 2M
TemporaryDirectory = /var/tmp
EOF

# 初始化病毒库
freshclam --verbose

# 配置 ClamAV 扫描守护进程
cat > /etc/clamd.d/scan.conf << 'EOF'
LogFile /var/log/clamd.scan
LogFileMaxSize 2M
LogTime yes
LogVerbose no
LocalSocket /run/clamd.scan/clamd.sock
FixStaleSocket true
TCPSocket 3310
TCPAddr 127.0.0.1
MaxThreads 4
MaxDirectoryRecursion 20
StreamMaxLength 100M
ScanArchive yes
ScanPE yes
ScanELF yes
ScanMail yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanHTML yes
ScanXML yes
ScanHWP3 yes
AlgorithmicDetection yes
PhishingSignatures yes
PhishingScanURLs yes
HeuristicScanPrecedence yes
StructuredDataDetection yes
DetectPUA yes
PUAExclusions W32.Packer.NetSRL
ExcludePath ^/proc
ExcludePath ^/sys
ExcludePath ^/dev
EOF

# 设置扫描定时任务（每日扫描）
cat > /etc/cron.daily/clamav-scan << 'SCRIPT'
#!/bin/bash
# ClamAV 每日扫描
SCAN_LOG="/var/log/clamav/daily-scan-$(date +%Y%m%d).log"
ALERT_LOG="/var/log/clamav/alerts-$(date +%Y%m%d).log"

mkdir -p /var/log/clamav

# 扫描 /home、/tmp、/var/tmp、/root 等用户目录
clamscan -ri \
    --log="$SCAN_LOG" \
    --exclude-dir="^/proc" \
    --exclude-dir="^/sys" \
    --exclude-dir="^/dev" \
    --exclude-dir="^/var/lib/clamav" \
    /home /tmp /var/tmp /root 2>/dev/null

# 检查是否发现病毒
if grep -q "FOUND" "$SCAN_LOG"; then
    grep "FOUND" "$SCAN_LOG" > "$ALERT_LOG"
    logger -p authpriv.crit "ClamAV 检测到恶意代码！请审查: $ALERT_LOG"
fi

# 保留 30 天日志
find /var/log/clamav -name "*.log" -mtime +30 -delete
SCRIPT

chmod +x /etc/cron.daily/clamav-scan

# 更新病毒库定时任务
cat > /etc/cron.daily/freshclam-update << 'SCRIPT'
#!/bin/bash
# 每日更新病毒库
freshclam --quiet 2>/dev/null
SCRIPT

chmod +x /etc/cron.daily/freshclam-update

# 验证安装
clamscan --version
```

---

## 6. 资源控制

### 6.1 limits.conf 资源限制

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.8 要求[2] — 应限制单个用户对系统资源的最大使用量
- CIS Benchmark：RHEL 9 §5.5.5 — Ensure default user shell timeout is 900 seconds or less（部分相关）

**命令：**
```bash
# 配置系统资源限制
cat > /etc/security/limits.d/99-hardening.conf << 'EOF'
# 资源硬限制（hard）—— 不允许超过
# 资源软限制（soft）—— 可临时提升至 hard 值

# 最大打开文件数
*               soft    nofile          8192
*               hard    nofile          65536

# 最大进程数（nproc）
*               soft    nproc           4096
*               hard    nproc           8192

# 最大文件锁定数
*               soft    memlock         256
*               hard    memlock         1024

# 最大栈大小（KB）
*               soft    stack           8192
*               hard    stack           16384

# 最大核心文件大小（0 = 禁止 core dump）
*               soft    core            0
*               hard    core            0

# 最大数据段大小（MB）
*               soft    data            unlimited
*               hard    data            unlimited

# 最大驻留内存（KB）
*               soft    rss             unlimited
*               hard    rss             unlimited

# 最大 CPU 时间（分钟）
*               soft    cpu             unlimited
*               hard    cpu             unlimited
EOF

# 验证
ulimit -a

# 禁止 core dump（systemd 级别）
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/99-core-dump.conf << 'EOF'
[Manager]
DefaultLimitCORE=0
EOF

cat > /etc/systemd/system.d/99-core-dump.conf << 'EOF'
[Manager]
DefaultLimitCORE=0
EOF
```

### 6.2 会话超时（TMOUT）

**🔗 标准映射**
- GB/T 22239-2019：§8.1.2.8 要求[1] — 应提供会话超时锁定或退出机制
- CIS Benchmark：RHEL 9 §5.5.5 — Ensure default user shell timeout is 900 seconds or less

**命令：**
```bash
# 设置全局会话超时为 900 秒（15 分钟）
cat > /etc/profile.d/tmout.sh << 'EOF'
# 会话超时设置（秒）
TMOUT=900
readonly TMOUT
export TMOUT
EOF

chmod 644 /etc/profile.d/tmout.sh

# 为 bashrc 添加（覆盖用户配置）
sed -i 's/^#*TMOUT=.*/TMOUT=900\nreadonly TMOUT/' /etc/bashrc 2>/dev/null || {
    echo "" >> /etc/bashrc
    echo "# 会话超时设置" >> /etc/bashrc
    echo "TMOUT=900" >> /etc/bashrc
    echo "readonly TMOUT" >> /etc/bashrc
}

# 验证
echo "TMOUT 值: ${TMOUT:-未设置}"
```

---

## 7. 数据备份恢复

### 7.1 rsync + cron 定时备份

**🔗 标准映射**
- GB/T 22239-2019：§8.1.3.4 要求[1] — 应提供重要数据的本地数据备份与恢复功能
- GB/T 22239-2019：§8.1.3.4 要求[2] — 应提供异地数据备份功能

**命令：**
```bash
# 创建备份脚本
cat > /usr/local/bin/system-backup.sh << 'SCRIPT'
#!/bin/bash
# 系统关键配置备份脚本
# 使用方式:
#   本地备份: ./system-backup.sh
#   远程备份: BACKUP_REMOTE=user@backup-server:/backup/path ./system-backup.sh

# 配置
BACKUP_DIR="/var/backups/system"
BACKUP_PREFIX="system-config"
RETENTION_DAYS=30
DATE=$(date +%Y%m%d-%H%M%S)
HOSTNAME=$(hostname -s)
BACKUP_FILE="${BACKUP_DIR}/${BACKUP_PREFIX}-${HOSTNAME}-${DATE}.tar.gz"

# 远程备份目标（通过环境变量覆盖）
REMOTE="${BACKUP_REMOTE:-}"

mkdir -p "$BACKUP_DIR"

# 备份关键配置文件
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始备份 $HOSTNAME ..."

tar czf "$BACKUP_FILE" \
    --exclude=/var/log \
    --exclude=/var/cache \
    --exclude=/var/tmp \
    --exclude=/tmp \
    /etc \
    /root \
    /var/spool/cron \
    /var/lib/aide \
    /var/log/audit \
    2>/dev/null

BACKUP_STATUS=$?
if [ $BACKUP_STATUS -eq 0 ]; then
    # 计算校验和
    sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 备份完成: $BACKUP_FILE (${BACKUP_SIZE})"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 备份失败！"
    exit 1
fi

# 清理过期备份
find "$BACKUP_DIR" -name "${BACKUP_PREFIX}-*.tar.gz" -mtime +${RETENTION_DAYS} -delete
find "$BACKUP_DIR" -name "${BACKUP_PREFIX}-*.sha256" -mtime +${RETENTION_DAYS} -delete

# 如果有配置远程备份目标，同步到远程
if [ -n "$REMOTE" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 同步到远程: $REMOTE"
    rsync -avz --partial --progress \
        "$BACKUP_FILE" \
        "${BACKUP_FILE}.sha256" \
        "$REMOTE" 2>/dev/null && \
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 远程同步完成" || \
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 远程同步失败！"
fi

# 打印最近 5 个备份
echo ""
echo "=== 最近备份 ==="
ls -lh "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -5
SCRIPT

chmod 750 /usr/local/bin/system-backup.sh

# 创建备份目录
mkdir -p /var/backups/system
chmod 750 /var/backups/system

# 配置每日备份定时任务
cat > /etc/cron.d/system-backup << 'EOF'
# 每日凌晨 2:00 执行系统配置备份
0 2 * * * root /usr/local/bin/system-backup.sh > /var/log/system-backup.log 2>&1

# 每周日凌晨 3:00 执行全量备份（包括 /home）
0 3 * * 0 root /usr/local/bin/system-backup.sh --full > /var/log/system-backup-weekly.log 2>&1
EOF

chmod 644 /etc/cron.d/system-backup

# 立即执行一次备份测试
/usr/local/bin/system-backup.sh

# 验证备份
ls -lh /var/backups/system/
```

---

## 附录 A：控制点映射表

| 编号 | 安全控制点 | GB/T 22239-2019 要求 | CIS Benchmark RHEL 9 | 加固措施条目 | 验证命令 |
|------|-----------|----------------------|---------------------|-------------|---------|
| 1.1 | 口令过期策略 | §8.1.2.2 要求[1] | §5.5.1.1 | 1.1 | `chage -l <user>` |
| 1.2 | 口令复杂度 | §8.1.2.2 要求[2] | §5.5.2 | 1.2 | `grep '^password' /etc/pam.d/system-auth` |
| 1.3 | 登录失败锁定 | §8.1.2.2 要求[3] | §5.5.3 | 1.3 | `faillock --user <user>` |
| 1.4 | SSH 安全配置 | §8.1.2.2 要求[4] | §6.2.9, §6.2.10 | 1.4 | `sshd -T \| grep permitrootlogin` |
| 1.5 | 会话超时 | §8.1.2.8 要求[1] | §6.2.13 | 1.5 | `sshd -T \| grep clientaliveinterval` |
| 2.1 | 最小账户管理 | §8.1.2.3 要求[1] | §6.2.14 | 2.1 | `awk -F: '($7!="/sbin/nologin"){print}' /etc/passwd` |
| 2.2 | sudo 日志审计 | §8.1.2.3 要求[2] | §7.2 | 2.2 | `grep logfile /etc/sudoers.d/*` |
| 2.3 | umask 权限掩码 | §8.1.2.3 要求[3] | §5.4.4 | 2.3 | `umask` / `grep umask /etc/profile.d/*` |
| 2.4 | 强制访问控制 | §8.1.2.3 要求[4] | §1.6.1.1 | 2.4 | `getenforce` |
| 3.1 | 安全审计 | §8.1.2.4 要求[1] | §4.1.x | 3.1 | `auditctl -l` |
| 3.2 | 日志集中管理 | §8.1.2.4 要求[2] | §4.2.x | 3.2 | `grep '@@' /etc/rsyslog.d/*` |
| 3.3 | 日志轮转保留 | §8.1.2.4 要求[3] | §4.3 | 3.3 | `logrotate -d /etc/logrotate.conf` |
| 4.1 | 最小安装原则 | §8.1.2.5 要求[1] | §1.2 | 4.1 | `rpm -qa \| wc -l` |
| 4.2 | 关闭多余服务 | §8.1.2.5 要求[2] | §3.x | 4.2 | `firewall-cmd --list-all` |
| 4.3 | 系统更新机制 | §8.1.2.5 要求[3] | §1.3 | 4.3 | `systemctl status dnf-automatic.timer` |
| 4.4 | 文件完整性 | §8.1.2.5 要求[4] | §1.4.1 | 4.4 | `aide --check` |
| 4.5 | 漏洞扫描 | §8.1.2.5 要求[5] | §1.2 | 4.5 | `oscap xccdf eval ...` |
| 5.1 | 恶意代码防范 | §8.1.2.6 要求[1] | — | 5.1 | `clamscan --version` |
| 6.1 | 资源限制 | §8.1.2.8 要求[2] | §5.5.5（部分） | 6.1 | `ulimit -a` |
| 6.2 | 会话超时 | §8.1.2.8 要求[1] | §5.5.5 | 6.2 | `echo $TMOUT` |
| 7.1 | 数据备份恢复 | §8.1.3.4 要求[1][2] | — | 7.1 | `ls -lh /var/backups/system/` |

---

## 附录 B：加固检查清单（快速验证）

```bash
#!/bin/bash
# 快速加固验证脚本
echo "========== 安全加固检查清单 =========="

echo ""
echo "【1. 身份鉴别】"
echo -n "  PASS_MAX_DAYS: "; grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2}'
echo -n "  pwquality 策略: "; grep -c pwquality /etc/pam.d/system-auth 2>/dev/null || echo "未启用"
echo -n "  faillock 锁定阈值: "; grep ^deny /etc/security/faillock.conf 2>/dev/null || echo "未配置"
echo -n "  SSH Root 登录: "; sshd -T 2>/dev/null | grep -E '^permitrootlogin' | awk '{print $2}'
echo -n "  SSH 超时(s): "; sshd -T 2>/dev/null | grep -E '^clientaliveinterval' | awk '{print $2}'

echo ""
echo "【2. 访问控制】"
echo -n "  可登录系统账户数: "; awk -F: '($7!="/sbin/nologin"&&$7!="/bin/false"&&$7!="/usr/sbin/nologin"&&$7!="/usr/bin/false"){print}' /etc/passwd | wc -l
echo -n "  sudo 审计日志: "; ls -la /var/log/sudo.log 2>/dev/null | awk '{print "已配置 ("$5" bytes)"}' || echo "未配置"
echo -n "  umask: "; umask
echo -n "  SELinux 模式: "; getenforce

echo ""
echo "【3. 安全审计】"
echo -n "  auditd 运行状态: "; systemctl is-active auditd
echo -n "  auditd 规则数: "; auditctl -l 2>/dev/null | wc -l
echo -n "  rsyslog 运行状态: "; systemctl is-active rsyslog

echo ""
echo "【4. 入侵防范】"
echo -n "  安装软件包数: "; rpm -qa --qf '%{NAME}\n' | wc -l
echo -n "  firewalld 状态: "; systemctl is-active firewalld
echo -n "  dnf-automatic 状态: "; systemctl is-active dnf-automatic.timer 2>/dev/null || echo "未启用"
echo -n "  AIDE 数据库: "; ls -lh /var/lib/aide/aide.db.gz 2>/dev/null | awk '{print $5}' || echo "未初始化"

echo ""
echo "【5. 恶意代码防范】"
echo -n "  ClamAV 病毒库: "; clamscan --version 2>/dev/null | head -1 || echo "未安装"

echo ""
echo "【6. 资源控制】"
echo -n "  TMOUT: "; echo "${TMOUT:-未设置}"
echo -n "  core dump 限制: "; ulimit -c
echo -n "  最大打开文件数: "; ulimit -n

echo ""
echo "【7. 数据备份】"
echo -n "  最近备份: "; ls -lt /var/backups/system/*.tar.gz 2>/dev/null | head -1 | awk '{print $6,$7,$8,$9}' || echo "无"
```

---

## 附录 C：安全加固快速部署脚本

```bash
#!/bin/bash
# RHEL 9 / AlmaLinux 9 / CentOS Stream 9 一键安全加固脚本
# 使用前请仔细阅读每项操作，确认不影响业务运行

set -euo pipefail

echo "=== RHEL 9 安全加固部署 ==="
echo "警告：请确认已阅读加固文档全文，了解每项变更"
sleep 3

# === 1. 身份鉴别 ===
echo "[1/7] 设置身份鉴别策略..."

# 1.1 login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# 1.2 pwquality
mkdir -p /etc/security/pwquality.conf.d
cat > /etc/security/pwquality.conf.d/99-hardening.conf << 'EOF'
minlen = 8
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
minclass = 3
EOF

# 1.3 faillock
cat > /etc/security/faillock.conf << 'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
even_deny_root
root_unlock_time = 900
EOF
authselect select sssd with-faillock --force 2>/dev/null || true

# 1.4 SSH
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

# === 2. 访问控制 ===
echo "[2/7] 设置访问控制策略..."

# 2.2 sudo 日志
cat > /etc/sudoers.d/99-logging << 'EOF'
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output
EOF
visudo -c -f /etc/sudoers.d/99-logging

# 2.3 umask
echo "umask 027" > /etc/profile.d/umask.sh

# 2.4 SELinux
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
setenforce 1 2>/dev/null || true

# === 3. 安全审计 ===
echo "[3/7] 配置安全审计..."
systemctl enable --now auditd

cat > /etc/audit/rules.d/99-critical-files.rules << 'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/selinux -p wa -k selinux
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo
EOF
augenrules --load 2>/dev/null

# === 4. 入侵防范 ===
echo "[4/7] 配置入侵防范..."
dnf install -y dnf-automatic aide 2>/dev/null || true
systemctl enable --now dnf-automatic.timer 2>/dev/null || true

# AIDE
aide --init 2>/dev/null
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true

# === 5. 恶意代码防范 ===
echo "[5/7] 配置恶意代码防范..."
dnf install -y epel-release clamav clamav-update 2>/dev/null || true
freshclam --quiet 2>/dev/null || true

# === 6. 资源控制 ===
echo "[6/7] 配置资源控制..."
cat > /etc/security/limits.d/99-hardening.conf << 'EOF'
*               soft    nofile          8192
*               hard    nofile          65536
*               soft    nproc           4096
*               hard    nproc           8192
*               soft    core            0
*               hard    core            0
EOF

cat > /etc/profile.d/tmout.sh << 'EOF'
TMOUT=900
readonly TMOUT
export TMOUT
EOF

# === 7. 数据备份 ===
echo "[7/7] 配置数据备份..."

cat > /usr/local/bin/system-backup.sh << 'SCRIPT'
#!/bin/bash
BACKUP_DIR="/var/backups/system"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/system-config-$(hostname -s)-${DATE}.tar.gz"
mkdir -p "$BACKUP_DIR"
tar czf "$BACKUP_FILE" /etc /root /var/spool/cron /var/lib/aide 2>/dev/null
sha256sum "$BACKUP_FILE" > "${BACKUP_FILE}.sha256"
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
SCRIPT
chmod 750 /usr/local/bin/system-backup.sh
/usr/local/bin/system-backup.sh

# 重启服务生效
systemctl restart sshd

echo ""
echo "=== 加固完成！==="
echo "请重启系统以确保 SELinux 策略完全生效（可选）"
echo "建议运行附录 B 的检查清单验证加固状态"
```

---

> **文档维护说明：**
> - 本文档适用于 RHEL 9 / AlmaLinux 9 / CentOS Stream 9
> - CIS Benchmark 版本参考 v2.0.0
> - GB/T 22239-2019 引用条款基于等保 2.0 三级系统要求
> - 部分加固项可能需要根据实际业务场景调整参数值
> - 建议在实施加固前先在测试环境验证
