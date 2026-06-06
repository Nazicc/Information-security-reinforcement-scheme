# 三级等保中间件加固方案 — Tomcat 9 & Nginx

> **说明：** 依据 GB/T 22239-2019 第三级安全要求编写，每条加固项标注控制点号 + CIS Benchmark 参考 + 配置命令。

---

## 一、Tomcat 9 加固

配置文件位于 `$CATALINA_BASE/conf/` 下。

### 1.1 身份鉴别

#### 1.1.1 用户密码加密存储

- **GB/T 22239-2019：** 身份鉴别 a)/b) — **CIS Tomcat v1.0.0：** 4.1/4.3
- **配置：** `$CATALINA_BASE/conf/server.xml`

```xml
<Resource name="UserDatabase" auth="Container"
          type="org.apache.catalina.users.MemoryUserDatabaseFactory"
          pathname="conf/tomcat-users.xml" digest="SHA-256"/>
```

```bash
# 生成摘要密码
$CATALINA_HOME/bin/digest.sh -a SHA-256 "your-password"
```

#### 1.1.2 移除默认账户

- **GB/T 22239-2019：** 身份鉴别 e) — **CIS Tomcat v1.0.0：** 4.2
- **配置：** `$CATALINA_BASE/conf/tomcat-users.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users version="1.0">
  <!-- 删除所有默认用户（tomcat/admin/manager），仅保留生产必需账户 -->
</tomcat-users>
```

#### 1.1.3 manager-gui 访问限制

- **GB/T 22239-2019：** 访问控制 a) — **CIS Tomcat v1.0.0：** 6.1/6.2
- **配置：** `$CATALINA_BASE/conf/Catalina/localhost/manager.xml`

```xml
<Context privileged="true" docBase="${catalina.home}/webapps/manager">
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"/>
</Context>
```

---

### 1.2 访问控制

#### 1.2.1 非 root 运行

- **GB/T 22239-2019：** 访问控制 c) — **CIS Tomcat v1.0.0：** 1.1
- **配置：** 创建专用系统用户

```bash
sudo useradd -r -s /sbin/nologin -d /opt/tomcat tomcat
sudo chown -R tomcat:tomcat /opt/tomcat
sudo -u tomcat $CATALINA_HOME/bin/startup.sh
```

#### 1.2.2 文件权限最小化

- **GB/T 22239-2019：** 访问控制 b) — **CIS Tomcat v1.0.0：** 1.2/1.3
- **配置：**

```bash
chmod 400 $CATALINA_BASE/conf/{server.xml,tomcat-users.xml,web.xml,catalina.properties}
chmod 750 $CATALINA_BASE/logs
```

#### 1.2.3 删除默认示例应用

- **GB/T 22239-2019：** 访问控制 d) — **CIS Tomcat v1.0.0：** 6.1
- **配置：**

```bash
rm -rf $CATALINA_BASE/webapps/{ROOT,examples,docs,host-manager}
```

#### 1.2.4 隐藏版本号

- **GB/T 22239-2019：** 安全计算环境 d) — **CIS Tomcat v1.0.0：** 3.1/3.2
- **配置：** `$CATALINA_BASE/conf/server.xml`

```xml
<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false"/>
```

```bash
# $CATALINA_BASE/conf/catalina.properties
# server.info=
# server.number=
```

---

### 1.3 安全审计

#### 1.3.1 启用访问日志

- **GB/T 22239-2019：** 安全审计 a)/b) — **CIS Tomcat v1.0.0：** 2.1/2.2
- **配置：** `$CATALINA_BASE/conf/server.xml`

```xml
<Valve className="org.apache.catalina.valves.AccessLogValve"
       directory="logs" prefix="localhost_access_log" suffix=".txt"
       pattern="%h %l %u %t &quot;%r&quot; %s %b %{X-Forwarded-For}i"
       resolveHosts="false" rotatable="true" fileDateFormat="yyyy-MM-dd"/>
```

#### 1.3.2 日志轮转

- **GB/T 22239-2019：** 安全审计 c) — **CIS：** 通用最佳实践
- **配置：** `/etc/logrotate.d/tomcat`

```
/opt/tomcat/logs/*.log /opt/tomcat/logs/*.txt /opt/tomcat/logs/*.out {
    daily rotate 90 compress delaycompress missingok copytruncate dateext
}
```

---

### 1.4 入侵防范

#### 1.4.1 禁用 AJP 连接器

- **GB/T 22239-2019：** 入侵防范 a)/b) — **CIS Tomcat v1.0.0：** 5.1
- **配置：** `$CATALINA_BASE/conf/server.xml`

```xml
<!-- 注释或删除 AJP 连接器 -->
<!-- <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" /> -->
```

#### 1.4.2 安全头配置

- **GB/T 22239-2019：** 入侵防范 d) — **CIS Tomcat v1.0.0：** 3.3/3.4
- **配置：** `$CATALINA_BASE/conf/web.xml`

```xml
<filter>
    <filter-name>httpHeaderSecurity</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <init-param><param-name>antiClickJackingOption</param-name><param-value>SAMEORIGIN</param-value></init-param>
    <init-param><param-name>xContentTypeNosniff</param-name><param-value>true</param-value></init-param>
    <init-param><param-name>xXSSProtection</param-name><param-value>1; mode=block</param-value></init-param>
    <init-param><param-name>hstsMaxAgeSeconds</param-name><param-value>31536000</param-value></init-param>
</filter>
<filter-mapping>
    <filter-name>httpHeaderSecurity</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

#### 1.4.3 HTTPS 强制跳转

- **GB/T 22239-2019：** 数据加密 b) — **CIS Tomcat v1.0.0：** 3.5
- **配置：** `$CATALINA_BASE/conf/web.xml`

```xml
<security-constraint>
    <web-resource-collection>
        <web-resource-name>All</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>
```

#### 1.4.4 连接器最大连接数限制

- **GB/T 22239-2019：** 入侵防范 c) — **CIS Tomcat v1.0.0：** 5.2
- **配置：** `$CATALINA_BASE/conf/server.xml`

```xml
<Connector port="8080" protocol="HTTP/1.1"
           connectionTimeout="20000" maxConnections="200"
           maxThreads="150" acceptCount="100" URIEncoding="UTF-8"/>
```

---

### 1.5 数据加密

#### 1.5.1 SSL/TLS 禁用弱协议

- **GB/T 22239-2019：** 数据加密 a) — **CIS Tomcat v1.0.0：** 5.3/5.4
- **配置：** `$CATALINA_BASE/conf/server.xml`

```xml
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           SSLEnabled="true" scheme="https" secure="true"
           sslProtocol="TLS" sslEnabledProtocols="TLSv1.2,TLSv1.3"
           ciphers="TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,
                    ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384">
    <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/keystore.jks"
                     certificateKeystorePassword="changeit" type="RSA"/>
    </SSLHostConfig>
</Connector>
```

```bash
# 验证弱协议已禁用
openssl s_client -connect localhost:8443 -ssl3 2>&1 | grep -i error
openssl s_client -connect localhost:8443 -tls1_2 2>&1 | grep -i "Protocol"
```

---

## 二、Nginx 加固

配置文件位于 `/etc/nginx/` 下。

### 2.1 身份鉴别

#### 2.1.1 HTTP Basic Auth

- **GB/T 22239-2019：** 身份鉴别 b)/d) — **CIS Nginx v1.0.0：** 5.1.1
- **配置：**

```bash
sudo htpasswd -c /etc/nginx/.htpasswd admin
```

```nginx
# /etc/nginx/conf.d/default.conf
location /admin/ {
    auth_basic           "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

#### 2.1.2 IP 访问限制

- **GB/T 22239-2019：** 访问控制 a) — **CIS Nginx v1.0.0：** 5.1.2
- **配置：**

```nginx
location /admin/ {
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    allow 127.0.0.1;
    deny  all;
}
```

---

### 2.2 访问控制

#### 2.2.1 非 root 运行

- **GB/T 22239-2019：** 访问控制 c) — **CIS Nginx v1.0.0：** 1.1.1
- **配置：** `/etc/nginx/nginx.conf`

```nginx
user  nginx;
worker_processes  auto;
```

```bash
# 验证 worker 进程未被 root 运行
ps aux | grep "nginx: worker" | grep -v grep
```

#### 2.2.2 目录遍历禁用

- **GB/T 22239-2019：** 访问控制 d) — **CIS Nginx v1.0.0：** 2.2.1
- **配置：** `/etc/nginx/nginx.conf`

```nginx
http {
    autoindex off;
    location ~ /\. { deny all; }
    location ~* \.(conf|yml|env|sql|log|bak|swp)$ { deny all; }
}
```

#### 2.2.3 隐藏版本号

- **GB/T 22239-2019：** 安全计算环境 d) — **CIS Nginx v1.0.0：** 2.1.1
- **配置：** `/etc/nginx/nginx.conf`

```nginx
http {
    server_tokens off;
}
```

#### 2.2.4 限制 HTTP 方法

- **GB/T 22239-2019：** 访问控制 d) — **CIS Nginx v1.0.0：** 2.3.1
- **配置：** `/etc/nginx/conf.d/default.conf`

```nginx
server {
    if ($request_method !~ ^(GET|POST|HEAD)$) {
        return 405;
    }
}
```

---

### 2.3 安全审计

#### 2.3.1 访问日志与 error log 级别

- **GB/T 22239-2019：** 安全审计 a)/b) — **CIS Nginx v1.0.0：** 3.1.1/3.1.2
- **配置：** `/etc/nginx/nginx.conf`

```nginx
http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main buffer=32k flush=5s;
    error_log /var/log/nginx/error.log warn;
}
```

#### 2.3.2 日志轮转

- **GB/T 22239-2019：** 安全审计 c) — **CIS：** 通用最佳实践
- **配置：** `/etc/logrotate.d/nginx`

```
/var/log/nginx/*.log {
    daily rotate 90 compress delaycompress
    missingok notifempty sharedscripts
    postrotate /usr/sbin/nginx -s reopen; endscript
}
```

---

### 2.4 入侵防范

#### 2.4.1 请求体大小限制

- **GB/T 22239-2019：** 入侵防范 c) — **CIS Nginx v1.0.0：** 4.1.1
- **配置：** `/etc/nginx/nginx.conf`

```nginx
http {
    client_max_body_size 10m;
}
```

#### 2.4.2 连接超时

- **GB/T 22239-2019：** 入侵防范 c) — **CIS Nginx v1.0.0：** 4.1.2
- **配置：** `/etc/nginx/nginx.conf`

```nginx
http {
    client_body_timeout   10s;
    client_header_timeout 10s;
    send_timeout          10s;
    keepalive_timeout     65s;
}
```

#### 2.4.3 限制并发连接

- **GB/T 22239-2019：** 入侵防范 c) — **CIS Nginx v1.0.0：** 4.1.3
- **配置：** `/etc/nginx/nginx.conf`

```nginx
http {
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_conn addr 10;
    limit_conn_status 429;
    limit_conn_log_level warn;

    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=5r/s;
}

# 在 server/location 中：
location / {
    limit_req zone=req_limit burst=10 nodelay;
}
```

#### 2.4.4 禁用不必要的模块

- **GB/T 22239-2019：** 入侵防范 a) — **CIS Nginx v1.0.0：** 1.2.1
- **配置：**

```bash
nginx -V 2>&1 | grep -- '--with' | tr ' ' '\n'

# 源码编译时禁用示例：
./configure \
  --without-http_autoindex_module \
  --without-http_ssi_module \
  --without-http_userid_module
```

---

### 2.5 数据加密

#### 2.5.1 TLS 配置

- **GB/T 22239-2019：** 数据加密 a) — **CIS Nginx v1.0.0：** 6.1.1/6.1.2/6.1.3
- **配置：** `/etc/nginx/conf.d/ssl.conf`

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    # 仅允许 TLSv1.2 / TLSv1.3，禁用 SSLv3 / TLSv1.0 / TLSv1.1
    ssl_protocols TLSv1.2 TLSv1.3;

    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
                ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
                DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
}
```

```bash
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
```

#### 2.5.2 HSTS

- **GB/T 22239-2019：** 数据加密 b) — **CIS Nginx v1.0.0：** 6.1.4
- **配置：** 在 SSL server 块中添加

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

#### 2.5.3 OCSP Stapling

- **GB/T 22239-2019：** 数据加密 a) — **CIS Nginx v1.0.0：** 6.2.1
- **配置：** 在 SSL server 块中添加

```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ssl/chain.pem;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

---

## 附录：控制点映射表

| GB/T 22239-2019 | 控制点名称 | Tomcat 9 | Nginx |
|---|---|---|---|
| 身份鉴别 a)/b) | 身份标识与鉴别 | 1.1.1 密码加密存储 | 2.1.1 Basic Auth |
| 身份鉴别 d) | 鉴别信息复杂度 | — | 2.1.1 密码文件 |
| 身份鉴别 e) | 默认账户清理 | 1.1.2 移除默认账户 | — |
| 访问控制 a) | 访问控制策略 | 1.1.3 manager限制 | 2.1.2 IP限制 |
| 访问控制 b) | 权限分离/最小权限 | 1.2.2 文件权限 | — |
| 访问控制 c) | 非特权用户运行 | 1.2.1 非root运行 | 2.2.1 非root运行 |
| 访问控制 d) | 限制默认/危险功能 | 1.2.3 删示例应用 | 2.2.2/2.2.4 目录遍历+方法限制 |
| 安全审计 a)/b) | 审计事件记录 | 1.3.1 访问日志 | 2.3.1 访问日志 |
| 安全审计 c) | 审计记录存储/轮转 | 1.3.2 日志轮转 | 2.3.2 日志轮转 |
| 入侵防范 a) | 最小化服务/端口 | 1.4.1 禁用AJP | 2.4.4 禁用不必要模块 |
| 入侵防范 b) | 攻击检测/防护 | 1.4.2 安全头配置 | — |
| 入侵防范 c) | 资源限制 | 1.4.4 最大连接数 | 2.4.1~2.4.3 限流/超时 |
| 入侵防范 d) | 防范 Web 攻击 | 1.4.2 安全头 | — |
| 数据加密 a) | 通信加密 | 1.5.1 SSL/TLS | 2.5.1/2.5.3 TLS+OCSP |
| 数据加密 b) | 加密通道强制 | 1.4.3 HTTPS跳转 | 2.5.2 HSTS |
| 安全计算环境 d) | 隐藏版本/信息泄露 | 1.2.4 隐藏版本号 | 2.2.3 隐藏版本号 |

---

> **文档版本：** v1.0 | **适用范围：** 三级等保 GB/T 22239-2019 | **适用组件：** Apache Tomcat 9 + Nginx
