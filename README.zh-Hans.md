<p align="center">
  一款集容器扫描，Docker和Kubernetes配置基线检查于一身的工具
</p>

<div align="center">
<strong>
<samp>

[English](README.md) · [简体中文](README.zh-Hans.md)

</samp>
</strong>
</div>

## 概述

vesta是一款集容器扫描，Docker和Kubernetes配置基线检查于一身的工具。检查内容包括镜像或容器中包含漏洞版本的组件，Docker以及Kubernetes的危险配置
<br/>
<br/>
vesta同时也是一个灵活，方便的工具，能够在各种系统上运行，包括但不限于Windows，Linux以及MacOS

<details>
<summary>
<font size="5"><b>Demo</b></font>
</summary>

<samp>

[![asciicast](https://asciinema.org/a/mtcyVDefFN8IXtv0abX8MA5MH.svg)](https://asciinema.org/a/mtcyVDefFN8IXtv0abX8MA5MH)

</samp>
</details>

---

## 编译并使用vesta

1. 编译vesta
- 使用`go build` 进行编译
- 从[Releases](https://github.com/kvesta/vesta/releases)上下载可执行文件
2. 使用vesta检查镜像过容器中的漏洞组件版本（使用镜像ID，镜像标签或使用`-f`文件输入均可）

```bash
$./vesta scan image -f example.tar

2022/11/29 22:50:00 Searching for image
2022/11/29 22:50:19 Begin upgrading vulnerability database
2022/11/29 22:50:19 Vulnerability Database is already initialized
2022/11/29 22:50:19 Begin to analyze the layer
2022/11/29 22:50:35 Begin to scan the layer

Detected 216 vulnerabilities

+-----+--------------------+-----------------+------------------+-------+----------+------------------------------------------------------------------+
| 208 | python3.6 - Django | 2.2.3           | CVE-2019-14232   |   7.5 | high     | An issue was discovered                                          |
|     |                    |                 |                  |       |          | in Django 1.11.x before                                          |
|     |                    |                 |                  |       |          | 1.11.23, 2.1.x before 2.1.11,                                    |
|     |                    |                 |                  |       |          | and 2.2.x before 2.2.4. If                                       |
|     |                    |                 |                  |       |          | django.utils.text.Truncator's                                    |
|     |                    |                 |                  |       |          | chars() and words() methods                                      |
|     |                    |                 |                  |       |          | were passed the html=True                                        |
|     |                    |                 |                  |       |          | argument, t ...                                                  |
+-----+                    +-----------------+------------------+-------+----------+------------------------------------------------------------------+
| 209 |                    | 2.2.3           | CVE-2019-14233   |   7.5 | high     | An issue was discovered                                          |
|     |                    |                 |                  |       |          | in Django 1.11.x before                                          |
|     |                    |                 |                  |       |          | 1.11.23, 2.1.x before 2.1.11,                                    |
|     |                    |                 |                  |       |          | and 2.2.x before 2.2.4.                                          |
|     |                    |                 |                  |       |          | Due to the behaviour of                                          |
|     |                    |                 |                  |       |          | the underlying HTMLParser,                                       |
|     |                    |                 |                  |       |          | django.utils.html.strip_tags                                     |
|     |                    |                 |                  |       |          | would be extremely ...                                           |
+-----+                    +-----------------+------------------+-------+----------+------------------------------------------------------------------+
| 210 |                    | 2.2.3           | CVE-2019-14234   |   9.8 | critical | An issue was discovered in                                       |
|     |                    |                 |                  |       |          | Django 1.11.x before 1.11.23,                                    |
|     |                    |                 |                  |       |          | 2.1.x before 2.1.11, and 2.2.x                                   |
|     |                    |                 |                  |       |          | before 2.2.4. Due to an error                                    |
|     |                    |                 |                  |       |          | in shallow key transformation,                                   |
|     |                    |                 |                  |       |          | key and index lookups for                                        |
|     |                    |                 |                  |       |          | django.contrib.postgres.f ...                                    |
+-----+--------------------+-----------------+------------------+-------+----------+------------------------------------------------------------------+

```

3. 使用vesta检查Docker的基线配置

```bash
$./vesta analyze docker

2022/11/29 23:06:32 Start analysing
2022/11/29 23:06:32 Geting engine version
2022/11/29 23:06:32 Geting docker server version
2022/11/29 23:06:32 Geting kernel version

Detected 3 vulnerabilities

+----+----------------------+----------------+---------------------------+----------+--------------------------------+
| ID |   CONTAINER DETAIL   |     PARAM      |           VALUE           | SEVERITY |          DESCRIPTION           |
+----+----------------------+----------------+---------------------------+----------+--------------------------------+
|  1 | Name: Kernel         | kernel version | 5.10.104-linuxkit         | critical | Kernel version is suffering    |
|    |  ID: None            |                |                           |          | the CVE-2022-0185 with         |
|    |                      |                |                           |          | CAP_SYS_ADMIN vulnerablility,  |
|    |                      |                |                           |          | has a potential container      |
|    |                      |                |                           |          | escape.                        |
+----+----------------------+----------------+---------------------------+----------+--------------------------------+
|    | Name: Image Tag      | Image Name     | nginx:latest              | low      | Using the latest tag will      |
|    |  ID: None            |                |                           |          | be suffered potential image    |
|    |                      |                |                           |          | hijack.                        |
+----+----------------------+----------------+---------------------------+----------+--------------------------------+
|  3 | Name: vesta_vuln_test| Privileged     | true                      | critical | There has a potential          |
|    |  ID: 207cf8842b15    |                |                           |          | container escape in privileged |
|    |                      |                |                           |          | module.                        |
+----+----------------------+----------------+---------------------------+----------+--------------------------------+
```

4. 使用vesta检查Kubernetes的基线配置

```bash
$./vesta analyze k8s

2022/11/29 23:15:59 Start analysing
2022/11/29 23:15:59 Geting docker server version
2022/11/29 23:15:59 Geting kernel version

Detected 4 vulnerabilities

Pods:
+----+--------------------+------------------------------+-------------------+-----------------------+----------+--------------------------------+
| ID |     POD DETAIL     |            PARAM             |       VALUE       |         TYPE          | SEVERITY |          DESCRIPTION           |
+----+--------------------+------------------------------+-------------------+-----------------------+----------+--------------------------------+
|  1 | Name: vulntest     | test-volume                  | /etc              | Directory             | critical | Mounting '/etc' is suffer      |
|    | Namespace: default |                              |                   |                       |          | vulnerable of container        |
|    |                    |                              |                   |                       |          | escape.                        |
+    +                    +------------------------------+-------------------+-----------------------+----------+--------------------------------+
|    |                    | Privileged                   | true              | Pod                   | critical | There has a potential          |
|    |                    |                              |                   |                       |          | container escape in privileged |
|    |                    |                              |                   |                       |          | module.                        |
+    +                    +------------------------------+-------------------+-----------------------+----------+--------------------------------+
|    |                    | AllowPrivilegeEscalation     | true              | Pod                   | critical | There has a potential          |
|    |                    |                              |                   |                       |          | container escape in privileged |
|    |                    |                              |                   |                       |          | module.                        |
+    +                    +------------------------------+-------------------+-----------------------+----------+--------------------------------+
|    |                    | Resource                     | memory, cpu,      | Pod                   | low      | None of resources is be        |
|    |                    |                              | ephemeral-storage |                       |          | limited.                       |
+----+--------------------+------------------------------+-------------------+-----------------------+----------+--------------------------------+

Configures:
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
| ID |            TYPEL            |             PARAM              |                         VALUE                          | SEVERITY |          DESCRIPTION           |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
|  1 | K8s version less than v1.24 | kernel version                 | 5.10.104-linuxkit                                      | critical | Kernel version is suffering    |
|    |                             |                                |                                                        |          | the CVE-2022-0185 with         |
|    |                             |                                |                                                        |          | CAP_SYS_ADMIN vulnerablility,  |
|    |                             |                                |                                                        |          | has a potential container      |
|    |                             |                                |                                                        |          | escape.                        |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
|  2 | ConfigMap                   | ConfigMap Name: vulnconfig     | db.string:mysql+pymysql://dbapp:Password123@db:3306/db | high     | ConfigMap has found weak       |
|    |                             | Namespace: default             |                                                        |          | password: 'Password123'.       |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
|  3 | Secret                      | Secret Name: vulnsecret-auth   | password:Password123                                   | high     | Secret has found weak          |
|    |                             | Namespace: default             |                                                        |          | password: 'Password123'.       |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
|  4 | ClusterRoleBinding          | binding name:                  | verbs:                                                 | high     | Key permission are given to    |
|    |                             | vuln-clusterrolebinding |      | get,watch,list,create,update |                         |          | the default service account    |
|    |                             | rolename: vuln-clusterrole |   | resources: pods,services                               |          | which will cause a potential   |
|    |                             | namespace: default             |                                                        |          | container escape.              |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
```

## 检查项

> Docker检查


| Supported | Check Item                | Description                                      | Severity                 |
|-----------|---------------------------|--------------------------------------------------|--------------------------|
| ✔         | PrivilegeAllowed          | 危险的特权模式                                          | critical                 |
| ✔         | Capabilities              | 危险capabilities被设置                                | critical                 |
| ✔         | Volume Mount              | 敏感或危险目录被挂载                                       | critical                 |
| ✔         | Docker Unauthorized       | 2375端口打开并且未授权                                    | critical                 |
| ✔         | Kernel version            | 当前内核版本存在逃逸漏洞                                     | critical                 |
| ✔         | Network Module            | Net模式为`host`模式并且在特定containerd版本下                 | critical                 |
| ✔         | Docker Server version     | Docker Server版本存在漏洞                              | critical/high/medium/low |
| ✔         | Docker env password check | Docker env是否存在弱密码                                | high/medium              |
| ✔         | Image tag check           | Image没有被打tag或为默认latest                           | low                      |
| 待定   | Container env             | 检查数据库是否未设置密码, 包括但不限于`MySQL`, `Redis`, `PostgreSQL` | -                        | 
| 待定          | IaC scan                  | IaC 扫描                                           | -                        |

---

> Kubernetes检查


| Supported | Check Item                                               | Description                                                     | Severity                 |
|-----------|----------------------------------------------------------|-----------------------------------------------------------------|--------------------------|
| ✔         | PrivilegeAllowed                                         | 危险的特权模式                                                         | critical                 |
| ✔         | Capabilities                                             | 危险capabilities被设置                                               | critical                 |
| ✔         | PV and PVC                                               | PV 被挂载到敏感目录并且状态为active                                          | critical/medium          |
| ✔         | ClusterRoleBinding                                       | 默认账户被赋予了权限                                                      | high/medium              |
| ✔         | Kubernetes-dashborad                                     | 检查 `-enable-skip-login`以及 dashborad的账户权限                        | critical/high/low        |
| ✔         | Kernel version (k8s versions is less than v1.24)         | 当前内核版本存在逃逸漏洞                                                    | critical                 |
| ✔         | Docker Server version  (k8s versions is less than v1.24) | Docker Server版本存在漏洞                                             | critical/high/medium/low |
| ✔         | Kubernetes certification expiration                      | 证书到期时间小于30天                                                     | medium                   |
| ✔         | ConfigMap and Secret check                               | ConfigMap 或者 Secret是否存在弱密码                                      | high/medium              |
| ✔         | Auto Mount ServiceAccount Token                          | Pod默认挂载了 `/var/run/secrets/kubernetes.io/serviceaccount/token`. | low                      |
| ✔         | NoResourceLimits                                         | 没有限制资源的使用，例如CPU,Memory, 存储                                      | low                      |
| ✔         | Job and Cronjob                                          | Job或CronJob没有设置seccomp或seLinux安全策略                              | low                      |
| ✔        | Envoy admin                                              | Envoy admin被配置以及监听`0.0.0.0`.                                    | high/medium              |
| 待定        | CVE-2022-29179                                           | 检测CVE-2022-29179是否存在                                            | critical                 |
| 待定        | Kubelet 10255 and Kubectl proxy                          | 10255 port 打开或 Kubectl proxy开启                                  | -                        |
| 待定        | Trampoline attack                                        | RBAC权限不安全，容易遭受Trampoline攻击                                      | -                        |
| 待定        | IaC scan                                                 | Iac扫描                                                           | -                        |


## 使用方法

```bash
$./vesta -h
Vesta is a static analysis of vulnerabilities, Docker and Kubernetes configuration detect toolkit
               Tutorial is available at https://github.com/kvesta/vesta

Usage:
  vesta [command]

Available Commands:
  analyze     Kubernetes analyze
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  scan        Container scan
  upgrade     Upgrade vulnerability database
  version     Print version information and quit

Flags:
  -h, --help   help for vesta
```
