# 数据库安全加固方案 — Oracle 19c & MySQL 8.0

> **适用标准：** GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》三级  
> **参考基准：** CIS Oracle Database 19c Benchmark v1.0 / CIS MySQL 8.0 Benchmark v2.0  
> **适用环境：** Oracle 19c（多租户架构 CDB/PDB）+ MySQL 8.0（InnoDB 存储引擎）

---

# 第一部分 Oracle 19c 加固

## 1.1 身份鉴别

### 1.1.1 密码策略

**控制点：** GB/T 22239-2019 三级 **身份鉴别 a)** — "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换。"

| 参数 | 推荐值 | 说明 |
|------|--------|------|
| `FAILED_LOGIN_ATTEMPTS` | 5 | 连续登录失败最大次数 |
| `PASSWORD_LIFE_TIME` | 90 | 密码最长使用期限（天） |
| `PASSWORD_GRACE_TIME` | 7 | 密码到期后宽限期（天） |
| `PASSWORD_LOCK_TIME` | 1 | 超过失败次数后账户锁定天数 |
| `PASSWORD_REUSE_TIME` | 365 | 密码可复用的最短间隔（天） |

**CIS 参考：** Oracle 19c CIS Benchmark §2.1 — "User Account and Password Security Settings"

```sql
-- 创建符合等保要求的 PROFILE（CDB 级别执行）
CREATE PROFILE C##GB_22239_PROFILE LIMIT
  FAILED_LOGIN_ATTEMPTS      5
  PASSWORD_LIFE_TIME         90
  PASSWORD_GRACE_TIME        7
  PASSWORD_LOCK_TIME         1
  PASSWORD_REUSE_TIME        365
  PASSWORD_REUSE_MAX         UNLIMITED
  PASSWORD_VERIFY_FUNCTION   NULL;

-- 应用到所有用户
ALTER USER SYS       PROFILE C##GB_22239_PROFILE;
ALTER USER SYSTEM    PROFILE C##GB_22239_PROFILE;

-- 查询当前所有用户的 PROFILE
SELECT username, profile, account_status
  FROM dba_users
  ORDER BY username;
```

若需启用密码复杂度验证函数（推荐）：

```sql
-- Oracle 提供默认的密码验证脚本
@?/rdbms/admin/utlpwdmg.sql

-- 查看创建后的函数名
SELECT object_name, object_type
  FROM dba_objects
  WHERE object_name LIKE '%PASSWORD%' AND object_type = 'FUNCTION';

-- 将验证函数应用到 PROFILE
ALTER PROFILE C##GB_22239_PROFILE LIMIT
  PASSWORD_VERIFY_FUNCTION ORA12C_VERIFY_FUNCTION;
```

### 1.1.2 远程连接加密

**控制点：** GB/T 22239-2019 三级 **身份鉴别 c)** — "当进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听。"

**CIS 参考：** Oracle 19c CIS Benchmark §3.1 — "Network Encryption"

配置 `$ORACLE_HOME/network/admin/sqlnet.ora`：

```ini
# 服务端强制加密
SQLNET.ENCRYPTION_SERVER = REQUIRED
SQLNET.ENCRYPTION_TYPES_SERVER = (AES256, AES192, AES128)
SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER = (SHA512, SHA384, SHA256)

# 客户端加密要求
SQLNET.ENCRYPTION_CLIENT = REQUIRED
SQLNET.ENCRYPTION_TYPES_CLIENT = (AES256, AES192, AES128)
SQLNET.CRYPTO_CHECKSUM_CLIENT = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT = (SHA512, SHA384, SHA256)

# 禁用旧版加密
SQLNET.ALLOW_WEAK_CRYPTO = FALSE
```

验证加密配置：

```sql
-- 查看当前会话的加密状态
SELECT network_service_banner
  FROM v$session_connect_info
  WHERE sid = SYS_CONTEXT('USERENV', 'SID');

-- 或从监听器日志验证
-- 期望看到: "AES256 Encryption service"
```

### 1.1.3 双因子认证说明

**控制点：** GB/T 22239-2019 三级 **身份鉴别 d)** — "应采用口令、密码技术、生物技术等两种或两种以上组合的鉴别技术对用户进行身份鉴别，且其中一种至少为密码技术。"

**说明：** Oracle 19c 支持以下多因子认证方式：

| 方案 | 说明 |
|------|------|
| **Oracle Advanced Security** | 支持 Kerberos、PKI（数字证书）、RADIUS 集成 |
| **多因素认证（MFA）** | 通过 RADIUS 代理集成 TOTP（Google Authenticator / RSA SecurID） |
| **SSL/TLS 客户端证书** | 双向 SSL 认证，客户端需提供合法证书 |

推荐方案（SSL 双向认证 + 口令）：

```sql
-- 配置数据库使用 SSL
-- 在 sqlnet.ora 中添加：
-- WALLET_LOCATION = (SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=/etc/oracle/wallet)))
-- SSL_CLIENT_AUTHENTICATION = TRUE

-- 创建钱包（需在 OS 命令行执行）
-- mkstore -wrl /etc/oracle/wallet -create
-- orapki wallet add -wallet /etc/oracle/wallet -dn "CN=server" -keysize 2048 -self_signed -validity 3650
```

### 1.1.4 移除默认密码账户

**控制点：** GB/T 22239-2019 三级 **身份鉴别 a)** — 确保身份标识具有唯一性，删除或锁定默认账户。

**CIS 参考：** Oracle 19c CIS Benchmark §2.2 — "Remove Default and Sample User Accounts"

```sql
-- 查询所有默认账户及其状态
SELECT username, account_status, profile, oracle_maintained
  FROM dba_users
  WHERE oracle_maintained = 'N'
  ORDER BY username;

-- 锁定内置演示账户
ALTER USER SCOTT   ACCOUNT LOCK;
ALTER USER HR      ACCOUNT LOCK;
ALTER USER OE      ACCOUNT LOCK;
ALTER USER PM      ACCOUNT LOCK;
ALTER USER IX      ACCOUNT LOCK;
ALTER USER SH      ACCOUNT LOCK;
ALTER USER BI      ACCOUNT LOCK;

-- 删除不需要的默认账户（谨慎操作，确认业务无依赖）
DROP USER SCOTT CASCADE;
DROP USER HR    CASCADE;
DROP USER OE    CASCADE;
DROP USER PM    CASCADE;
DROP USER IX    CASCADE;
DROP USER SH    CASCADE;
DROP USER BI    CASCADE;

-- 验证：检查无业务关联的默认账户是否已全部锁定或删除
SELECT username, account_status, created
  FROM dba_users
  WHERE oracle_maintained = 'N' AND account_status = 'OPEN';
```

---

## 1.2 访问控制

### 1.2.1 最小权限原则 — 角色分离

**控制点：** GB/T 22239-2019 三级 **访问控制 a)** — "应对登录的用户分配账户和权限。"

**CIS 参考：** Oracle 19c CIS Benchmark §4.1 — "Privileges and Grants"

```sql
-- 查看 DBA 角色授予情况（仅限真正需要的人）
SELECT grantee, granted_role, admin_option, default_role
  FROM dba_role_privs
  WHERE granted_role = 'DBA'
  ORDER BY grantee;

-- 查看特定用户拥有的系统权限
SELECT * FROM dba_sys_privs WHERE grantee = '&USERNAME';
SELECT * FROM dba_tab_privs WHERE grantee = '&USERNAME';

-- 撤销不必要的 DBA 权限
REVOKE DBA FROM &USERNAME;

-- 按需授予最小权限（示例：只读用户）
CREATE ROLE READONLY_ROLE;
GRANT CREATE SESSION TO READONLY_ROLE;
GRANT SELECT ANY TABLE TO READONLY_ROLE;     -- 按需收窄
GRANT SELECT ON sys.dba_data_files TO READONLY_ROLE;

-- 为应用服务账号创建专用角色
CREATE ROLE APP_READ_ROLE;
GRANT SELECT ON app_schema.orders TO APP_READ_ROLE;
GRANT SELECT ON app_schema.customers TO APP_READ_ROLE;
GRANT APP_READ_ROLE TO app_user;
```

### 1.2.2 审计视图权限保护

**控制点：** GB/T 22239-2019 三级 **访问控制 b)** — "应根据管理需要授予用户所需的最小权限。"

**CIS 参考：** Oracle 19c CIS Benchmark §5.1 — "Audit Data Protection"

```sql
-- 保护审计数据，仅允许审计管理员访问
-- 撤销非审计管理员对审计视图的访问
REVOKE SELECT ON sys.aud$ FROM PUBLIC;
REVOKE SELECT ON sys.dba_audit_trail FROM PUBLIC;
REVOKE SELECT ON sys.unified_audit_trail FROM PUBLIC;

-- 为审计管理员创建专用角色
CREATE ROLE AUDIT_ADMIN_ROLE;
GRANT AUDIT_ADMIN TO AUDIT_ADMIN_ROLE;
GRANT SELECT ON sys.unified_audit_trail TO AUDIT_ADMIN_ROLE;

-- 确认授权情况
SELECT grantee, table_name, privilege
  FROM dba_tab_privs
  WHERE table_name IN ('AUD$', 'UNIFIED_AUDIT_TRAIL', 'DBA_AUDIT_TRAIL');
```

### 1.2.3 数据库对象 OWNER 权限检查

**控制点：** GB/T 22239-2019 三级 **访问控制 c)** — "应授予不同账户为完成各自承担任务所需的最小权限。"

**CIS 参考：** Oracle 19c CIS Benchmark §4.2 — "Object Ownership and Permission"

```sql
-- 查找所有者为非 SYS/SYSTEM 的系统级对象（潜在风险）
SELECT owner, object_name, object_type, status
  FROM dba_objects
  WHERE owner NOT IN ('SYS','SYSTEM','XDB','SYSTEM','DBSNMP','OJVMSYS')
    AND object_type IN ('SYNONYM','VIEW','PROCEDURE','PACKAGE')
    AND owner IN (SELECT username FROM dba_users WHERE oracle_maintained = 'N')
  ORDER BY owner, object_type;

-- 查找 PUBLIC 同义词，评估是否必要
SELECT owner, synonym_name, table_owner, table_name, db_link
  FROM dba_synonyms
  WHERE owner = 'PUBLIC'
  ORDER BY synonym_name;

-- 撤销不必要的 PUBLIC 权限
REVOKE EXECUTE ON UTL_FILE FROM PUBLIC;
REVOKE EXECUTE ON UTL_HTTP FROM PUBLIC;
REVOKE EXECUTE ON UTL_SMTP FROM PUBLIC;
REVOKE EXECUTE ON UTL_TCP  FROM PUBLIC;

-- 检查 DBA_TAB_PRIVS 中 PUBLIC 的权限
SELECT table_name, privilege, grantable
  FROM dba_tab_privs
  WHERE grantee = 'PUBLIC' AND owner = 'SYS'
  ORDER BY table_name;
```

---

## 1.3 安全审计

### 1.3.1 启用统一审计

**控制点：** GB/T 22239-2019 三级 **安全审计 a)** — "应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计。"

**CIS 参考：** Oracle 19c CIS Benchmark §5 — "Auditing"

```sql
-- 检查统一审计是否启用
SELECT VALUE FROM v$option WHERE PARAMETER = 'Unified Auditing';

-- 如果返回 FALSE，需要在 OS 级别配置
-- cd $ORACLE_HOME/rdbms/lib
-- make -f ins_rdbms.mk uniaud_on iam_on
-- 重启数据库
-- SQL> SHUTDOWN IMMEDIATE;
-- SQL> STARTUP;

-- 启用统一审计策略
-- 创建审计策略：审计 DBA 操作
CREATE AUDIT POLICY dba_operations_policy
  ACTIONS ALL
  WHEN 'SYS_CONTEXT(''USERENV'',''ISDBA'') = ''TRUE'''
  CONTAINER = ALL;

AUDIT POLICY dba_operations_policy;

-- 创建审计策略：审计 DDL 操作
CREATE AUDIT POLICY ddl_operations_policy
  ACTIONS CREATE TABLE, DROP TABLE, ALTER TABLE,
         CREATE INDEX, DROP INDEX,
         CREATE USER, DROP USER, ALTER USER,
         CREATE ROLE, DROP ROLE,
         CREATE TABLESPACE, DROP TABLESPACE,
         CREATE PROCEDURE, DROP PROCEDURE,
         GRANT, REVOKE
  CONTAINER = ALL;

AUDIT POLICY ddl_operations_policy;

-- 创建审计策略：审计登录/登出
CREATE AUDIT POLICY login_logout_policy
  ACTIONS LOGON, LOGOFF
  CONTAINER = ALL;

AUDIT POLICY login_logout_policy;

-- 查看已启用的审计策略
SELECT * FROM audit_unified_enabled_policies;

-- 查看审计记录
SELECT os_username, username, action_name, return_code,
       to_char(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_time
  FROM unified_audit_trail
  WHERE rownum <= 100
  ORDER BY event_timestamp DESC;
```

### 1.3.2 审计关键操作

**控制点：** GB/T 22239-2019 三级 **安全审计 b)** — "审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等。"

**CIS 参考：** Oracle 19c CIS Benchmark §5.2 — "Audit Critical Privileged Actions"

```sql
-- 细粒度审计：关键系统权限使用
CREATE AUDIT POLICY critical_privilege_usage_policy
  PRIVILEGES ALTER ANY TABLE, DROP ANY TABLE,
             ALTER ANY PROCEDURE, DROP ANY PROCEDURE,
             ALTER SYSTEM,
             CREATE ANY JOB,
             EXEMPT ACCESS POLICY,
             BECOME USER,
             DROP ANY INDEX,
             DROP ANY TABLESPACE
  CONTAINER = ALL;

AUDIT POLICY critical_privilege_usage_policy;

-- 审计所有 GRANT/REVOKE 操作
CREATE AUDIT POLICY grant_revoke_policy
  ACTIONS GRANT, REVOKE
  CONTAINER = ALL;

AUDIT POLICY grant_revoke_policy;

-- 审计数据导出相关操作
CREATE AUDIT POLICY data_export_policy
  ACTIONS CREATE DIRECTORY, DROP DIRECTORY,
         EXECUTE ON SYS.UTL_FILE,
         SELECT ON SYS.DMP_DIR
  CONTAINER = ALL;

AUDIT POLICY data_export_policy;
```

### 1.3.3 审计日志保护

**控制点：** GB/T 22239-2019 三级 **安全审计 c)** — "应对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖等。"

**CIS 参考：** Oracle 19c CIS Benchmark §5.3 — "Protect Audit Data"

```sql
-- 设置审计表空间（分离存放，防止占满 SYSTEM）
CREATE TABLESPACE AUDIT_DATA
  DATAFILE '/u01/oradata/orcl/audit01.dbf' SIZE 1G AUTOEXTEND ON NEXT 256M
  EXTENT MANAGEMENT LOCAL SEGMENT SPACE MANAGEMENT AUTO;

-- 将审计表移至专用表空间
ALTER TABLE sys.unified_audit_trail MOVE TABLESPACE AUDIT_DATA;

-- 设置审计日志归档目标
ALTER SYSTEM SET AUDIT_FILE_DEST = '/u01/app/oracle/admin/orcl/adump_secure' SCOPE=BOTH;

-- 配置审计日志保留策略（30 天）
BEGIN
  DBMS_AUDIT_MGMT.SET_LAST_ARCHIVE_TIMESTAMP(
    audit_trail_type => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
    last_archive_time => SYSTIMESTAMP - 30
  );
END;
/

-- 配置自动清理（启用清理作业）
BEGIN
  DBMS_AUDIT_MGMT.INIT_CLEANUP(
    audit_trail_type         => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
    default_cleanup_interval => 24 /* 小时 */
  );
END;
/

-- 清理超过 90 天的审计记录
BEGIN
  DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(
    audit_trail_type => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
    use_last_arch_timestamp => TRUE
  );
END;
/
```

---

## 1.4 入侵防范

### 1.4.1 最小化安装组件

**控制点：** GB/T 22239-2019 三级 **入侵防范 a)** — "应遵循最小安装原则，仅安装需要的组件和应用程序。"

**CIS 参考：** Oracle 19c CIS Benchmark §1.1 — "Minimize Software Installation"

```sql
-- 查询已安装的数据库组件
SELECT comp_name, version, status, modified
  FROM dba_registry
  ORDER BY comp_name;

-- 查询已安装的数据库选项
SELECT * FROM v$option WHERE parameter IN (
  'Oracle Data Mining',
  'Oracle Spatial',
  'Oracle Text',
  'Oracle Multimedia',
  'Oracle OLAP',
  'Oracle Label Security',
  'Oracle Database Vault'
);

-- 卸载不必要的组件（以 Oracle Text 为例）
-- 注意：卸载操作需在业务窗口进行，影响不可逆
-- BEGIN
--   DBMS_REGISTRY.DOWNLOADING('CONTEXT');
--   ...
-- END;
-- /

-- 最小化安装建议：仅保留核心组件
-- 除以下组件外，评估是否可移除：
-- - JServer JAVA 虚拟机（若无 Java 存储过程需求）
-- - Oracle XDB（若无需 XML DB 功能）
-- - Oracle Multimedia（若无需多媒体数据）
-- - Oracle OLAP（若无需在线分析处理）
```

### 1.4.2 禁用不必要的数据库功能

**控制点：** GB/T 22239-2019 三级 **入侵防范 b)** — "应关闭不需要的系统服务、默认共享和高危端口。"

**CIS 参考：** Oracle 19c CIS Benchmark §4.4 — "Disable Unnecessary Network and PL/SQL Features"

```sql
-- 1) 撤销高危 PL/SQL 包的 PUBLIC 执行权限
REVOKE EXECUTE ON UTL_HTTP  FROM PUBLIC;
REVOKE EXECUTE ON UTL_SMTP  FROM PUBLIC;
REVOKE EXECUTE ON UTL_TCP   FROM PUBLIC;
REVOKE EXECUTE ON UTL_FILE  FROM PUBLIC;
REVOKE EXECUTE ON UTL_INADDR FROM PUBLIC;
REVOKE EXECUTE ON DBMS_RANDOM FROM PUBLIC;
REVOKE EXECUTE ON DBMS_SCHEDULER FROM PUBLIC;
REVOKE EXECUTE ON DBMS_LOB   FROM PUBLIC;
REVOKE EXECUTE ON DBMS_LOCK  FROM PUBLIC;

-- 验证权限撤销
SELECT grantee, table_name, privilege
  FROM dba_tab_privs
  WHERE table_name IN ('UTL_HTTP','UTL_SMTP','UTL_TCP','UTL_FILE','UTL_INADDR',
                       'DBMS_RANDOM','DBMS_SCHEDULER')
    AND grantee = 'PUBLIC';

-- 2) 关闭不必要的 XML DB 协议端口
-- 检查 FTP/HTTP 服务端口
SELECT dbms_xdb_config.gethttpport()   AS http_port FROM dual;
SELECT dbms_xdb_config.getftpport()    AS ftp_port FROM dual;

-- 关闭不需要的端口
BEGIN
  DBMS_XDB_CONFIG.SETHTTPSPORT(0);
  DBMS_XDB_CONFIG.SETFTPPORT(0);
END;
/

-- 3) 禁用远程 DDL 执行（仅 DBA 可通过网络执行 DDL）
-- 在 sqlnet.ora 中限制 IP
-- tcp.validnode_checking=yes
-- tcp.invited_nodes=(10.0.0.0/24, 172.16.0.0/12)
-- tcp.excluded_nodes=(10.0.0.0/8)
```

### 1.4.3 数据库补丁管理（PSU/RU）

**控制点：** GB/T 22239-2019 三级 **入侵防范 c)** — "应确保系统在最小漏洞暴露下运行，及时更新补丁。"

**CIS 参考：** Oracle 19c CIS Benchmark §1.2 — "Patch Management"

```sql
-- 查看当前数据库版本和补丁级别
SELECT * FROM v$version;

-- 查看已安装的补丁（OPatch 方式）
SELECT patch_id, patch_type, action, status, description, action_time
  FROM dba_registry_sqlpatch
  ORDER BY action_time DESC;

-- 查看最新 RU 季度补丁信息
SELECT * FROM v$system_fix_control
  WHERE fix_number > (SELECT MAX(fix_number) FROM v$system_fix_control) - 10;

-- 补丁管理操作流程（OS 层面）：
-- # 1. 关闭数据库
-- SQL> SHUTDOWN IMMEDIATE;
--
-- # 2. 备份 Oracle Home
-- $ tar -czf $ORACLE_HOME/../backup_oh_$(date +%Y%m%d).tar.gz $ORACLE_HOME
--
-- # 3. 应用补丁
-- $ cd $ORACLE_HOME/OPatch
-- $ ./opatch apply /path/to/p34231567_190000_Linux-x86-64.zip
--
-- # 4. 执行 SQL 脚本
-- $ cd $ORACLE_HOME/rdbms/admin
-- $ sqlplus / as sysdba
-- SQL> STARTUP
-- SQL> @catcon.pl -d . -b postinstall -l /tmp postinstall.sql
--
-- # 5. 验证补丁
-- $ ./opatch lsinventory
```

---

## 1.5 数据加密

### 1.5.1 传输加密配置

**控制点：** GB/T 22239-2019 三级 **数据加密 b)** — "应采用密码技术保证重要数据在传输过程中的机密性。"

**CIS 参考：** Oracle 19c CIS Benchmark §3.1 — "Network Encryption"（同 1.1.2 节）

此部分配置已在 1.1.2 节详述。以下是补充的 SSL/TLS 完整配置：

```ini
# $ORACLE_HOME/network/admin/sqlnet.ora — SSL 完整配置
WALLET_LOCATION =
  (SOURCE = (METHOD = FILE)
    (METHOD_DATA = (DIRECTORY = /etc/oracle/wallet)))

SSL_CLIENT_AUTHENTICATION = TRUE
SSL_VERSION = 1.2

SQLNET.ENCRYPTION_SERVER = REQUIRED
SQLNET.ENCRYPTION_TYPES_SERVER = (AES256, AES192)
SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER = (SHA512, SHA384)

SSL_CIPHER_SUITES = (SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                     SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384)

SQLNET.ALLOW_WEAK_CRYPTO = FALSE
```

### 1.5.2 透明数据加密（TDE）介绍

**控制点：** GB/T 22239-2019 三级 **数据加密 a)** — "应采用密码技术保证重要数据在存储过程中的机密性。"

**CIS 参考：** Oracle 19c CIS Benchmark §6.1 — "Transparent Data Encryption"

**注意：TDE 需要 Oracle Advanced Security 选项授权。**

```sql
-- 1. 创建加密钱包目录（OS 层面）
-- mkdir -p /etc/oracle/wallet

-- 2. 配置 sqlnet.ora
-- ENCRYPTION_WALLET_LOCATION =
--   (SOURCE = (METHOD = FILE)
--     (METHOD_DATA = (DIRECTORY = /etc/oracle/wallet)))

-- 3. 创建并打开加密钱包
ADMINISTER KEY MANAGEMENT CREATE KEYSTORE '/etc/oracle/wallet'
  IDENTIFIED BY "WalletP@ssw0rd";

ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN
  IDENTIFIED BY "WalletP@ssw0rd";

ADMINISTER KEY MANAGEMENT SET KEY
  IDENTIFIED BY "WalletP@ssw0rd"
  WITH BACKUP;

-- 4. 创建自动登录钱包（方便重启）
ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE
  FROM KEYSTORE '/etc/oracle/wallet'
  IDENTIFIED BY "WalletP@ssw0rd";

-- 5. 加密表空间
CREATE TABLESPACE secure_data
  DATAFILE '/u01/oradata/orcl/secure01.dbf' SIZE 500M
  ENCRYPTION USING 'AES256'
  DEFAULT STORAGE(ENCRYPT);

-- 或对现有表空间启用加密
ALTER TABLESPACE users ENCRYPTION ONLINE USING 'AES256';

-- 6. 加密现有的表
ALTER TABLE app_schema.credit_cards MODIFY ENCRYPTION;

-- 7. 查看加密对象
SELECT tablespace_name, encrypted, encryption_algorithm
  FROM dba_tablespaces
  WHERE encrypted = 'YES';

SELECT owner, table_name, encryption_algorithm
  FROM dba_encrypted_tables;
```

### 1.5.3 备份加密

**控制点：** GB/T 22239-2019 三级 **数据加密 c)** — "应配置备份策略对重要数据进行备份，备份数据应加密存储。"

```sql
-- RMAN 备份加密配置
-- 1. 设置加密算法
RMAN> CONFIGURE ENCRYPTION FOR DATABASE ON;
RMAN> CONFIGURE ENCRYPTION ALGORITHM 'AES256';

-- 2. 加密完整备份
RMAN> BACKUP DATABASE PLUS ARCHIVELOG;

-- 3. 加密增量备份
RMAN> BACKUP INCREMENTAL LEVEL 1 DATABASE;

-- 4. 验证备份加密
RMAN> VALIDATE BACKUPSET ALL;

-- 5. 加密备份的恢复（需要正确的加密钱包配置）
-- RMAN> SET DECRYPTION IDENTIFIED BY "WalletP@ssw0rd";
-- RMAN> RESTORE DATABASE;
-- RMAN> RECOVER DATABASE;
```

---

## 1.6 资源控制

### 1.6.1 资源限制（PROFILE）

**控制点：** GB/T 22239-2019 三级 **资源控制 a)** — "应通过设定终端接入方式、网络地址范围等条件限制终端登录。"

**CIS 参考：** Oracle 19c CIS Benchmark §2.3 — "Resource Limits"

```sql
-- 创建资源限制 Profile
CREATE PROFILE C##RESOURCE_LIMIT_PROFILE LIMIT
  -- 会话控制
  SESSIONS_PER_USER             2       -- 每个用户最多并发会话数
  CONNECT_TIME                  120     -- 单次连接最大时间（分钟）
  IDLE_TIME                     30      -- 空闲超时（分钟）
  
  -- CPU 资源
  CPU_PER_SESSION               UNLIMITED -- 每个会话 CPU 时间限制（秒）
  CPU_PER_CALL                  600     -- 每次调用 CPU 时间（秒）
  
  -- I/O 资源
  LOGICAL_READS_PER_SESSION     UNLIMITED -- 每个会话逻辑读限制
  LOGICAL_READS_PER_CALL        10000   -- 每次调用逻辑读限制
  
  -- 其他
  PRIVATE_SGA                    512K   -- 私有 SGA 空间限制
  COMPOSITE_LIMIT               UNLIMITED;

-- 应用到用户
ALTER USER app_user PROFILE C##RESOURCE_LIMIT_PROFILE;

-- 启用资源限制（需在系统级别开启）
ALTER SYSTEM SET RESOURCE_LIMIT = TRUE SCOPE = BOTH;

-- 验证资源限制生效
SELECT username, profile
  FROM dba_users
  WHERE profile = 'C##RESOURCE_LIMIT_PROFILE';
```

---

# 第二部分 MySQL 8.0 加固

## 2.1 身份鉴别

### 2.1.1 密码策略（validate_password 组件）

**控制点：** GB/T 22239-2019 三级 **身份鉴别 a)** — "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §2.5 — "Password Complexity"

```sql
-- 安装 validate_password 组件
INSTALL COMPONENT 'file://component_validate_password';

-- 验证组件已安装
SELECT COMPONENT_URN, STATUS
  FROM mysql.component;

-- 配置密码策略
SET PERSIST validate_password.policy = 'STRONG';        -- 0=LOW, 1=MEDIUM, 2=STRONG
SET PERSIST validate_password.length = 12;               -- 最小长度
SET PERSIST validate_password.mixed_case_count = 1;      -- 大小写字母至少各 1
SET PERSIST validate_password.number_count = 1;          -- 数字至少 1
SET PERSIST validate_password.special_char_count = 1;    -- 特殊字符至少 1

-- 查看密码策略配置
SHOW VARIABLES LIKE 'validate_password%';

-- 测试密码强度
SELECT VALIDATE_PASSWORD_STRENGTH('MyStr0ng!Pass');
-- 返回值：0=弱, 25=一般, 50=中等, 75=强, 100=非常强
```

### 2.1.2 账户锁定策略

**控制点：** GB/T 22239-2019 三级 **身份鉴别 b)** — "应具有登录失败处理功能，配置并启用结束会话、限制非法登录次数和当登录连接超时自动退出等相关措施。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §2.6 — "Account Locking"

```sql
-- 注意：MySQL 8.0 的 FAILED_LOGIN_ATTEMPTS 和 PASSWORD_LOCK_TIME
-- 需配合 password_reuse_interval 插件或通过 CONNECTION_CONTROL 插件实现

-- 安装连接控制插件
INSTALL PLUGIN CONNECTION_CONTROL           SONAME 'connection_control.so';
INSTALL PLUGIN CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS SONAME 'connection_control.so';

-- 验证插件状态
SHOW PLUGINS;

-- 配置登录失败策略
SET PERSIST connection_control_failed_login_threshold = 5;    -- 连续失败 5 次后触发延迟
SET PERSIST connection_control_min_connection_delay = 1000;   -- 最小延迟 1 秒
SET PERSIST connection_control_max_connection_delay = 86400000; -- 最大延迟 24 小时

-- 创建用户时直接设置密码过期和账户锁定策略
-- MySQL 8.0 支持在 CREATE USER 时指定：
CREATE USER 'app_user'@'10.0.0.%'
  IDENTIFIED BY 'MyStr0ng!Pass'
  PASSWORD EXPIRE INTERVAL 90 DAY          -- 密码 90 天过期
  FAILED_LOGIN_ATTEMPTS 5                  -- 5 次失败锁定（需 password_history 插件）
  PASSWORD_LOCK_TIME 1                     -- 锁定 1 天
  ACCOUNT UNLOCK;

-- 查看用户锁定状态
SELECT user, host, account_locked, password_expired, password_last_changed
  FROM mysql.user
  WHERE user NOT IN ('mysql.session', 'mysql.sys');

-- 手动锁定/解锁账户
ALTER USER 'app_user'@'10.0.0.%' ACCOUNT LOCK;
ALTER USER 'app_user'@'10.0.0.%' ACCOUNT UNLOCK;
```

### 2.1.3 移除匿名账户和默认数据库

**控制点：** GB/T 22239-2019 三级 **身份鉴别 a)** — "应删除或重命名默认账户。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §2.1 — "Remove Anonymous Accounts"

```sql
-- 查询匿名账户（用户名为空）
SELECT user, host, authentication_string
  FROM mysql.user
  WHERE user = '' OR user IS NULL;

-- 删除匿名账户
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS ''@'%';
DROP USER IF EXISTS ''@'127.0.0.1';

-- 删除默认的测试数据库
SELECT schema_name FROM information_schema.schemata
  WHERE schema_name IN ('test', 'mysql_test');

DROP DATABASE IF EXISTS test;
DROP DATABASE IF EXISTS mysql_test;

-- 删除 test 用户的默认访问
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'test'@'%';
DROP USER IF EXISTS 'test'@'%';
DROP USER IF EXISTS 'test'@'localhost';

-- 验证清理结果
SELECT user, host, account_locked FROM mysql.user
  WHERE user NOT IN ('mysql.session', 'mysql.sys');
```

### 2.1.4 远程连接限制

**控制点：** GB/T 22239-2019 三级 **身份鉴别 c)** — "当进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §3.1 — "Network Security"

```ini
# my.cnf 配置 — 绑定地址和网络限制
[mysqld]
# 仅监听内网接口（根据实际网络规划配置）
bind-address = 10.0.0.100

# 禁用网络连接（如果仅本地访问）
# skip-networking

# 是否跳过 DNS 反向解析（提升性能，减少 DNS 攻击面）
skip-name-resolve

# 最大连接数
max_connections = 500

# 超时设置
wait_timeout = 600              # 非交互连接超时（秒）
interactive_timeout = 28800     # 交互连接超时（秒）（内部用户建议 3600）
```

```sql
-- 远程连接限制——用户 HOST 管控
-- 原则：禁止使用 '%' 通配符，精确指定来源 IP

-- 查看所有用户的 HOST
SELECT user, host, account_locked
  FROM mysql.user
  WHERE user NOT IN ('mysql.session', 'mysql.sys');

-- 创建精确 IP 范围的用户
-- 示例：仅允许内网段 10.0.0.0/24 访问
CREATE USER 'dba_admin'@'10.0.0.%' IDENTIFIED BY 'Str0ng!AdminPass';
CREATE USER 'app_user'@'10.0.0.50' IDENTIFIED BY 'App!Us3rPass';

-- 移除 % 通配符用户
DROP USER IF EXISTS 'root'@'%';
DROP USER IF EXISTS 'app_user'@'%';

-- 设置 root 仅限本地登录
RENAME USER 'root'@'%' TO 'root'@'localhost';
-- 或直接删除
-- DROP USER IF EXISTS 'root'@'%';
```

### 2.1.5 SSL/TLS 连接配置

**控制点：** GB/T 22239-2019 三级 **身份鉴别 c)** — "当进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §3.2 — "SSL/TLS Configuration"

```sql
-- 检查当前 SSL 状态
SHOW VARIABLES LIKE '%ssl%';
SHOW STATUS LIKE 'Ssl%';

-- 检查是否所有远程用户都需要 SSL
SELECT user, host, ssl_type, ssl_cipher
  FROM mysql.user
  WHERE host NOT IN ('localhost', '127.0.0.1', '::1');

-- 要求特定用户必须使用 SSL
ALTER USER 'app_user'@'10.0.0.%' REQUIRE SSL;
-- 或要求指定加密
ALTER USER 'dba_admin'@'10.0.0.%' REQUIRE CIPHER 'ECDHE-ECDSA-AES256-GCM-SHA384';
```

```ini
# my.cnf SSL 完整配置
[mysqld]
# SSL 证书路径
ssl_ca = /etc/mysql/ssl/ca.pem
ssl_cert = /etc/mysql/ssl/server-cert.pem
ssl_key = /etc/mysql/ssl/server-key.pem

# 要求所有连接使用 SSL（谨慎使用，会影响本地 socket 连接）
# require_secure_transport = ON

# 指定 TLS 版本（禁用旧版 TLS）
tls_version = TLSv1.2,TLSv1.3

# SSL 加密算法
ssl_cipher = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# 创建自签名证书参考命令（OS 层面）：
# mysql_ssl_rsa_setup --uid=mysql --datadir=/var/lib/mysql
```

---

## 2.2 访问控制

### 2.2.1 最小权限原则

**控制点：** GB/T 22239-2019 三级 **访问控制 b)** — "应根据管理需要授予用户所需的最小权限。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §4.1 — "User Privileges"

```sql
-- 查看所有用户的全局权限
SELECT user, host, Grant_priv, Super_priv, File_priv, Create_tmp_table_priv,
       Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv
  FROM mysql.user
  WHERE user NOT IN ('mysql.session', 'mysql.sys')
  ORDER BY user;

-- 最小权限原则：精确到表级授权

-- 错误做法：全局大范围授权
-- GRANT ALL PRIVILEGES ON *.* TO 'app_user'@'10.0.0.%';   -- ❌ 禁止

-- 正确做法：精确到表级
CREATE DATABASE IF NOT EXISTS app_db;
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'10.0.0.%';
-- 或更精确：
GRANT SELECT ON app_db.orders TO 'readonly_user'@'10.0.0.%';

-- 只读用户
CREATE USER 'readonly_user'@'10.0.0.%' IDENTIFIED BY 'ReadOnly!2024';
GRANT SELECT ON app_db.* TO 'readonly_user'@'10.0.0.%';

-- 应用写用户（仅增删改查，无 DDL）
CREATE USER 'app_write'@'10.0.0.50' IDENTIFIED BY 'AppWrite!2024';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_write'@'10.0.0.50';

-- 应用 DDL 用户（表结构变更专用）
CREATE USER 'app_ddl'@'10.0.0.50' IDENTIFIED BY 'AppDDL!2024';
GRANT CREATE, ALTER, DROP, INDEX ON app_db.* TO 'app_ddl'@'10.0.0.50';

-- 查看库级权限
SELECT * FROM information_schema.schema_privileges
  WHERE grantee NOT LIKE "'mysql.%'";
```

### 2.2.2 移除 FILE / SUPER / PROCESS 等危险权限

**控制点：** GB/T 22239-2019 三级 **访问控制 c)** — "应授予不同账户为完成各自承担任务所需的最小权限。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §4.2 — "Restrict Dangerous Privileges"

```sql
-- 查询拥有高危权限的用户
SELECT user, host,
  File_priv           AS 'FILE',      -- 可读写服务器文件
  Super_priv          AS 'SUPER',     -- 超级权限
  Process_priv        AS 'PROCESS',   -- 可查看所有线程
  Create_tmp_table_priv AS 'CREATE_TMP',
  Lock_tables_priv    AS 'LOCK_TABLES',
  Shutdown_priv       AS 'SHUTDOWN',
  Repl_slave_priv     AS 'REPL_SLAVE'
FROM mysql.user
WHERE user NOT IN ('mysql.session', 'mysql.sys')
  AND (File_priv = 'Y' OR Super_priv = 'Y' OR Process_priv = 'Y');

-- 撤销非必需的高危权限
REVOKE FILE ON *.* FROM 'app_user'@'10.0.0.%';
REVOKE SUPER ON *.* FROM 'app_user'@'10.0.0.%';
REVOKE PROCESS ON *.* FROM 'app_user'@'10.0.0.%';
REVOKE SHUTDOWN ON *.* FROM 'app_user'@'10.0.0.%';

-- 仅保留给真正需要的管理账户
-- root 保留全部权限；运维监控账号可保留 PROCESS

-- 刷新权限
FLUSH PRIVILEGES;
```

### 2.2.3 数据库名与用户分离

**控制点：** GB/T 22239-2019 三级 **访问控制 a)** — "应对登录的用户分配账户和权限。"

```sql
-- 不允许多个应用共用同一个数据库账号
-- 每种业务应有独立的数据库和账号

-- 示例：多租户隔离方案
CREATE DATABASE IF NOT EXISTS finance_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS hr_db      CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS order_db   CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 每个业务独立的用户
CREATE USER 'finance_app'@'10.0.0.%' IDENTIFIED BY 'Finance!2024';
CREATE USER 'hr_app'@'10.0.0.%'      IDENTIFIED BY 'HR!2024';
CREATE USER 'order_app'@'10.0.0.%'   IDENTIFIED BY 'Order!2024';

-- 按需授权
GRANT SELECT, INSERT, UPDATE, DELETE ON finance_db.* TO 'finance_app'@'10.0.0.%';
GRANT SELECT, INSERT, UPDATE, DELETE ON hr_db.*      TO 'hr_app'@'10.0.0.%';
GRANT SELECT, INSERT, UPDATE, DELETE ON order_db.*    TO 'order_app'@'10.0.0.%';
```

---

## 2.3 安全审计

### 2.3.1 General Log 配置

**控制点：** GB/T 22239-2019 三级 **安全审计 a)** — "应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §5.1 — "Audit Logging"

```ini
# my.cnf — General Query Log（仅用于调试，生产环境谨慎开启）
[mysqld]
# General Log 配置（生产环境建议关闭 general_log，使用 audit_log）
general_log = OFF
# general_log_file = /var/log/mysql/general.log
```

### 2.3.2 audit_log 插件配置

**控制点：** GB/T 22239-2019 三级 **安全审计 a)** — "应启用安全审计功能，审计覆盖到每个用户。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §5.2 — "Audit Plugin Configuration"

```sql
-- 安装 audit_log 插件（MySQL Enterprise 或 MariaDB Audit 插件）
-- MySQL Enterprise Audit：
-- INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- 或使用 Percona Server 的 audit_log 插件
-- INSTALL PLUGIN audit_log SONAME 'audit_log_filter.so';

-- 验证插件安装
SHOW PLUGINS;

-- 查看审计配置
SHOW VARIABLES LIKE 'audit_log%';
```

```ini
# my.cnf — Audit Log 配置
[mysqld]
# 启用审计日志
audit_log = ON

# 审计日志文件路径
audit_log_file = /var/log/mysql/audit.log

# 审计日志格式（JSON 或 XML，推荐 JSON）
audit_log_format = JSON

# 审计策略：记录所有操作
audit_log_policy = ALL

# 审计策略可选值：
# ALL       - 记录所有操作
# LOGINS    - 仅记录登录事件
# QUERIES   - 仅记录查询事件
# LOGINS_AND_QUERIES - 记录登录和查询

# 审计缓冲区
audit_log_buffer_size = 4M

# 日志轮转
audit_log_rotate_on_size = 100M
audit_log_rotations = 10

# 建议配置（如使用 Percona audit_log_filter）：
# audit_log_exclude_accounts = 'root@localhost,system_user@localhost'
# audit_log_include_accounts = 'app_user@10.0.0.%'
# audit_log_exclude_commands = 'BEGIN,COMMIT,ROLLBACK'
```

### 2.3.3 二进制日志管理

**控制点：** GB/T 22239-2019 三级 **安全审计 b)** — "审计记录应包括事件的日期、时间、类型、主体标识、客体标识和结果等。"

```ini
# my.cnf — 二进制日志配置
[mysqld]
# 启用二进制日志（也是审计的重要来源）
log_bin = /var/log/mysql/mysql-bin.log

# 二进制日志格式
binlog_format = ROW          # ROW 级别记录，保留完整变更

# 二进制日志保留策略
binlog_expire_logs_seconds = 2592000  # 保留 30 天（30*86400）

# 或旧语法（MySQL 8.0 兼容）：
# expire_logs_days = 30

# binlog 文件最大大小
max_binlog_size = 500M

# 安全的 binlog 设置
sync_binlog = 1              # 每次事务提交后同步
innodb_flush_log_at_trx_commit = 1  # InnoDB 日志同步
```

```sql
-- 查看二进制日志状态
SHOW MASTER STATUS;
SHOW VARIABLES LIKE 'log_bin%';
SHOW VARIABLES LIKE 'binlog_expire%';

-- 查看二进制日志列表
SHOW BINARY LOGS;

-- 手动清理旧日志（需谨慎，确认备份完成后执行）
PURGE BINARY LOGS BEFORE NOW() - INTERVAL 30 DAY;

-- 查看二进制日志内容（需要 mysqlbinlog 工具）
-- $ mysqlbinlog --no-defaults /var/log/mysql/mysql-bin.000001
```

---

## 2.4 入侵防范

### 2.4.1 禁用 LOAD DATA LOCAL

**控制点：** GB/T 22239-2019 三级 **入侵防范 b)** — "应关闭不需要的系统服务、默认共享和高危端口。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §3.4 — "Disable LOAD DATA LOCAL"

```ini
# my.cnf — 禁用 LOAD DATA LOCAL
[mysqld]
# 禁用服务端 local-infile
local-infile = 0

[client]
# 禁用客户端 local-infile
local-infile = 0

[mysql]
local-infile = 0

[mysqld_safe]
local-infile = 0
```

```sql
-- 验证 local-infile 已禁用
SHOW VARIABLES LIKE 'local_infile';

-- 确认返回:
-- +---------------+-------+
-- | Variable_name | Value |
-- +---------------+-------+
-- | local_infile  | OFF   |
-- +---------------+-------+
```

### 2.4.2 禁用 symbolic-links

**控制点：** GB/T 22239-2019 三级 **入侵防范 a)** — "应遵循最小安装原则，仅安装需要的组件和应用程序。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §3.6 — "Disable Symbolic Links"

```ini
# my.cnf — 禁用符号链接
[mysqld]
# 禁用所有数据库表级别的符号链接
skip_symbolic_links = ON

# 以下为旧版参数（MySQL 8.0 已弃用），确认均关闭
# safe-updates = 1    # UPDATE/DELETE 必须带 WHERE
# skip-show-database  # 限制 SHOW DATABASES
```

```sql
-- 检查符号链接设置
SHOW VARIABLES LIKE 'have_symlink';
SHOW VARIABLES LIKE 'skip_symbolic_links';
SHOW VARIABLES LIKE 'log_bin_trust_function_creators';

-- 确保 log_bin_trust_function_creators 为 OFF（避免安全风险）
SET PERSIST log_bin_trust_function_creators = 0;
```

### 2.4.3 local-infile=0（补充验证）

同 2.4.1 节。补充安全相关配置：

```ini
# my.cnf — 其他入侵防范相关配置
[mysqld]
# 禁用旧版 mysql_native_password
default_authentication_plugin = caching_sha2_password

# OLTP 参数安全建议
sql_mode = STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,PIPES_AS_CONCAT,ANSI_QUOTES

# 禁用远程 root 登录（已在账户管理部分实施）
```

### 2.4.4 补丁管理

**控制点：** GB/T 22239-2019 三级 **入侵防范 c)** — "应确保系统在最小漏洞暴露下运行，及时更新补丁。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §1.1 — "Keep Software Updated"

```sql
-- 查看 MySQL 版本信息
SHOW VARIABLES LIKE 'version%';
SELECT VERSION();

-- 查看已安装的插件和组件
SHOW COMPONENT STATUS;
SELECT * FROM mysql.component;

-- 补丁更新流程
-- 1. 下载新版本或补丁包
--    $ wget https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-8.0.36-linux-glibc2.28-x86_64.tar.xz
--
-- 2. 备份数据
--    $ mysqldump --all-databases --source-data=2 > /backup/mysql_$(date +%Y%m%d).sql
--
-- 3. 停止 MySQL
--    $ systemctl stop mysql
--
-- 4. 备份原有二进制
--    $ cp -r /usr/local/mysql /usr/local/mysql.bak_$(date +%Y%m%d)
--
-- 5. 替换二进制文件
--    $ tar xf mysql-8.0.36-linux-glibc2.28-x86_64.tar.xz -C /usr/local/
--    $ mv /usr/local/mysql /usr/local/mysql.old
--    $ ln -s /usr/local/mysql-8.0.36-linux-glibc2.28-x86_64 /usr/local/mysql
--
-- 6. 启动 MySQL 并运行 mysql_upgrade
--    $ systemctl start mysql
--    $ mysql_upgrade -u root -p
--
-- 7. 验证版本
--    mysql> SELECT VERSION();
```

---

## 2.5 数据加密

### 2.5.1 SSL/TLS 传输加密

**控制点：** GB/T 22239-2019 三级 **数据加密 b)** — "应采用密码技术保证重要数据在传输过程中的机密性。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §3.2 — "SSL/TLS Configuration"

SSL/TLS 配置已在 2.1.5 节详述。补充验证命令：

```sql
-- 验证当前所有连接是否加密
SELECT id, user, host, ssl_cipher, ssl_sessions_reused
  FROM performance_schema.session_status
  WHERE variable_name = 'Ssl_cipher';

-- 或查看活跃连接
SELECT thread_id, user, host, ssl_version, ssl_cipher
  FROM performance_schema.threads
  WHERE type = 'FOREGROUND' AND user NOT LIKE '%event%';

-- 要求特定用户强制使用 SSL
ALTER USER 'app_user'@'10.0.0.%' REQUIRE SSL;

-- 创建 SSL 强制用户
CREATE USER 'secure_user'@'10.0.0.%'
  IDENTIFIED BY 'Str0ng!S3cur3'
  REQUIRE SSL;
```

### 2.5.2 表空间加密（InnoDB 透明加密）

**控制点：** GB/T 22239-2019 三级 **数据加密 a)** — "应采用密码技术保证重要数据在存储过程中的机密性。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §6.1 — "Data at Rest Encryption"

```sql
-- 检查 InnoDB 加密支持
SHOW VARIABLES LIKE 'innodb_undo_log_encrypt';
SHOW VARIABLES LIKE 'innodb_redo_log_encrypt';
SHOW VARIABLES LIKE 'table_encryption_privilege_check';

-- 检查 InnoDB page 大小（需先确认，影响加解密开销）
SHOW VARIABLES LIKE 'innodb_page_size';

-- 1. 生成密钥环文件（OS 层面）
-- MySQL 8.0 使用 keyring_file 插件或 component_keyring_file 组件
-- INSTALL COMPONENT 'file://component_keyring_file';

-- 2. 配置 my.cnf
-- [mysqld]
-- early-plugin-load = keyring_file.so
-- keyring_file_data = /var/lib/mysql-keyring/keyring

-- 3. 启用表空间加密
SET PERSIST default_table_encryption = ON;

-- 4. 创建加密表空间
CREATE TABLESPACE encrypted_ts ADD DATAFILE 'encrypted_ts.ibd'
  ENCRYPTION = 'Y'
  ENCRYPTION_KEY_ID = 1
  ENGINE = InnoDB;

-- 5. 在加密表空间中创建表
CREATE TABLE secure_data.credit_cards (
  id INT PRIMARY KEY AUTO_INCREMENT,
  card_number VARCHAR(20) NOT NULL,
  card_holder VARCHAR(100) NOT NULL,
  expiry_date DATE NOT NULL
) TABLESPACE encrypted_ts ENGINE = InnoDB;

-- 6. 对现有表启用表空间加密
ALTER TABLE app_db.orders ENCRYPTION = 'Y';

-- 7. 启用 Redo Log 加密和 Undo Log 加密
SET PERSIST innodb_redo_log_encrypt = ON;
SET PERSIST innodb_undo_log_encrypt = ON;

-- 8. 查看加密对象
SELECT TABLE_SCHEMA, TABLE_NAME, CREATE_OPTIONS
  FROM information_schema.TABLES
  WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%';

-- 9. 检查密钥环状态
SELECT * FROM performance_schema.keyring_keys;
```

```ini
# my.cnf — 完整加密配置
[mysqld]
# 密钥环组件（MySQL 8.0.24+ 推荐使用组件）
# keyring_component = keyring_component_file.so
# keyring_component_file = /var/lib/mysql-keyring/keyring_component_file

# 传统 keyring 文件插件
early-plugin-load = keyring_file.so
keyring_file_data = /var/lib/mysql-keyring/keyring

# 表空间加密
default_table_encryption = ON
table_encryption_privilege_check = ON

# Redo/Undo 日志加密
innodb_redo_log_encrypt = ON
innodb_undo_log_encrypt = ON

# 双写文件加密
innodb_encrypt_online_alter_logs = ON
```

---

## 2.6 资源控制

### 2.6.1 max_user_connections

**控制点：** GB/T 22239-2019 三级 **资源控制 a)** — "应通过设定终端接入方式、网络地址范围等条件限制终端登录。"

**CIS 参考：** MySQL 8.0 CIS Benchmark §7.1 — "Resource Limits"

```ini
# my.cnf — 资源限制
[mysqld]
# 全局最大连接数
max_connections = 500

# 每个用户的最大连接数（全局默认）
max_user_connections = 50
```

```sql
-- 设置每个用户的连接限制
ALTER USER 'app_user'@'10.0.0.%' WITH
  MAX_QUERIES_PER_HOUR 10000
  MAX_UPDATES_PER_HOUR 5000
  MAX_CONNECTIONS_PER_HOUR 100
  MAX_USER_CONNECTIONS 10;

-- 查看用户的资源限制
SELECT user, host, max_questions, max_updates, max_connections, max_user_connections
  FROM mysql.user
  WHERE user NOT IN ('mysql.session', 'mysql.sys');

-- 资源计数重置（通常在服务重启后重置，也可手动重置）
-- FLUSH USER_RESOURCES;
```

### 2.6.2 max_connections 限制

**控制点：** GB/T 22239-2019 三级 **资源控制 b)** — "应根据安全策略设置登录终端的操作超时和锁定策略。"

```sql
-- 查看当前连接数和限制
SHOW VARIABLES LIKE 'max_connections';
SHOW STATUS LIKE 'Max_used_connections';
SHOW STATUS LIKE 'Threads_connected';

-- 计算连接使用率
SELECT
  VARIABLE_VALUE AS max_connections,
  (SELECT VARIABLE_VALUE FROM performance_schema.global_status
   WHERE VARIABLE_NAME = 'Threads_connected') AS current_connections,
  ROUND(
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Threads_connected') /
    VARIABLE_VALUE * 100, 2
  ) AS usage_pct
FROM performance_schema.global_variables
WHERE VARIABLE_NAME = 'max_connections';

-- 动态调整（临时）
SET GLOBAL max_connections = 500;

-- 持久化调整
SET PERSIST max_connections = 500;
```

### 2.6.3 查询超时控制

**控制点：** GB/T 22239-2019 三级 **资源控制 c)** — "应限制单个用户的多重并发会话与连接。"

```ini
# my.cnf — 查询超时控制
[mysqld]
# 只读查询超时（建议 60 秒以内）
max_execution_time = 60000         # 毫秒

# 事务超时（超过此时间自动回滚）
innodb_lock_wait_timeout = 30      # 秒

# 交互式超时（对 mysql/mysqldump 等交互工具）
interactive_timeout = 28800        # 秒，建议缩至 3600

# 非交互式超时（应用连接）
wait_timeout = 600                 # 秒

# DDL 超时
lock_wait_timeout = 600            # 秒
```

```sql
-- 设置会话级别超时（针对特定会话）
SET SESSION max_execution_time = 30000;       -- 30 秒
SET SESSION innodb_lock_wait_timeout = 10;    -- 10 秒

-- 查看慢查询阈值
SHOW VARIABLES LIKE 'long_query_time';

-- 配置慢查询日志（辅助资源控制）
SET PERSIST slow_query_log = ON;
SET PERSIST long_query_time = 2;              -- 慢查询阈值（秒）

-- 使用资源组（MySQL 8.0 特性）
CREATE RESOURCE GROUP batch_group
  TYPE = USER
  VCPU = 0-3
  THREAD_PRIORITY = 0;

CREATE RESOURCE GROUP report_group
  TYPE = USER
  VCPU = 4-7
  THREAD_PRIORITY = 5;

SET RESOURCE GROUP report_group;
-- 之后执行的查询使用 report_group 资源限制
```

---

# 附录：控制点映射表

## GB/T 22239-2019 三级 = Oracle 19c + MySQL 8.0 加固映射

| 控制点 | 等保要求 | Oracle 19c 对应措施 | MySQL 8.0 对应措施 |
|--------|----------|---------------------|--------------------|
| **身份鉴别 a)** | 身份标识唯一性、鉴别信息复杂度并定期更换 | PROFILE 密码策略、密码复杂度函数、移除默认账户 | validate_password 组件、密码过期策略、移除匿名账户 |
| **身份鉴别 b)** | 登录失败处理、会话超时 | FAILED_LOGIN_ATTEMPTS、PASSWORD_LOCK_TIME、IDLE_TIME | connection_control 插件、FAILED_LOGIN_ATTEMPTS、wait_timeout |
| **身份鉴别 c)** | 远程管理防止鉴别信息窃听 | SQL*Net 加密（sqlnet.ora） | SSL/TLS 配置、require_secure_transport |
| **身份鉴别 d)** | 两种以上鉴别技术组合 | Advanced Security（SSL + 口令/RADIUS） | SSL + 口令认证 |
| **访问控制 a)** | 分配账户和权限 | 角色分离、最小权限原则 | GRANT 精确到表级、CREATE USER HOST 限制 |
| **访问控制 b)** | 授予最小权限 | 审计视图权限保护、撤销 PUBLIC 权限 | 撤销 FILE/SUPER/PROCESS、精确授权 |
| **访问控制 c)** | 不同账户不同权限 | 对象 OWNER 权限检查、角色分离 | 数据库名与用户分离、业务隔离 |
| **安全审计 a)** | 启用审计，覆盖每个用户 | Unified Auditing、审计策略 | audit_log 插件、binlog 管理 |
| **安全审计 b)** | 审计记录完整（时间、类型、主体等） | unified_audit_trail 完整记录 | binlog ROW 格式、JSON 格式审计日志 |
| **安全审计 c)** | 审计记录保护、备份 | 审计表空间隔离、自动清理策略 | 审计日志轮转、binlog 保留策略 |
| **入侵防范 a)** | 最小化安装 | 卸载不必要组件、禁用 XDB 端口 | 移除 test 库、禁用不需要的插件 |
| **入侵防范 b)** | 关闭不需要的服务/端口 | 撤销 UTL_* 包权限、关闭 XML DB 端口 | 禁用 LOAD DATA LOCAL、symbolic-links |
| **入侵防范 c)** | 补丁更新管理 | OPatch、PSU/RU 季度更新 | MySQL 版本更新、安全补丁 |
| **数据加密 a)** | 存储机密性 | TDE 表空间加密 | InnoDB 表空间加密、redo/undo 加密 |
| **数据加密 b)** | 传输机密性 | SQL*Net AES256 加密 | SSL/TLS ECDHE-AES256-GCM |
| **数据加密 c)** | 备份加密 | RMAN 备份 AES256 加密 | mysqldump 加密 + 备份卷加密 |
| **资源控制 a)** | 限制终端接入 | RESOURCE_LIMIT、PROFILE 限制 | max_connections、max_user_connections |
| **资源控制 b)** | 超时锁定策略 | CONNECT_TIME、IDLE_TIME | wait_timeout、interactive_timeout |
| **资源控制 c)** | 限制并发会话 | SESSIONS_PER_USER | max_user_connections、资源组 |

---

## CIS Benchmark 章节索引

| 安全域 | Oracle 19c CIS Benchmark | MySQL 8.0 CIS Benchmark |
|--------|-------------------------|------------------------|
| 补丁与版本 | §1.2 Patch Management | §1.1 Keep Software Updated |
| 密码策略 | §2.1 Password Settings | §2.5 Password Complexity |
| 账户管理 | §2.2 Remove Default Accounts | §2.1 Remove Anonymous Accounts |
| 资源限制 | §2.3 Resource Limits | §7.1 Resource Limits |
| 网络加密 | §3.1 Network Encryption | §3.2 SSL/TLS Configuration |
| 高危功能 | §3.4 Disable Unnecessary Features | §3.4 Disable LOAD DATA LOCAL |
| 权限管理 | §4.1 Privileges and Grants | §4.1 User Privileges |
| 高危权限 | §4.2 Object Ownership | §4.2 Restrict Dangerous Privileges |
| 审计 | §5 Auditing | §5.2 Audit Plugin Configuration |
| 审计保护 | §5.3 Protect Audit Data | §5.1 Audit Logging |
| 数据加密 | §6.1 Transparent Data Encryption | §6.1 Data at Rest Encryption |

---

> **文档维护记录**  
> 制定日期：2026-06-06  
> 适用版本：Oracle 19c (19.3+) / MySQL 8.0 (8.0.24+)  
> 依据标准：GB/T 22239-2019 三级 / CIS Benchmark  
> 
> **注意事项：**  
> 1. 所有 SQL 命令应在测试环境验证后，再批量推送到生产环境。  
> 2. 涉及数据加密、权限回收等敏感操作，应提前评估业务影响范围。  
> 3. TDE、Advanced Security 等需要额外 License 授权的功能，请确认授权后再启用。  
> 4. 审计日志的保留周期应根据企业实际合规要求（如《网络安全法》至少 6 个月）进行调整。
