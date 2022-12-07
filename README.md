<p align="center">
  A static analysis of vulnerabilities, Docker and Kubernetes cluster configuration detect toolkit
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
cluster pods, and containers with safe practices. It also analyses image or container components with an extra python module and node npm scan.
<br/>
<br/>
Vesta is a flexible toolkit which can run on physical machines in different types of systems (Windows, Linux, MacOS).

## Build

Vesta is built with Go 1.18. 

```bash
go build
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
2022/11/29 22:50:00 Searching image
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

Example of docker config scan, start vesta:

```bash
vesta analyze docker
```

Output:

```bash
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

Example of Kubernetes config scan, start vesta:

```bash
vesta analyze k8s
```

Output:

```bash
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
+----+-----------------------------+--------------------------------+--------------------------------+----------+--------------------------------+
| ID |            TYPEL            |             PARAM              |             VALUE              | SEVERITY |          DESCRIPTION           |
+----+-----------------------------+--------------------------------+--------------------------------+----------+--------------------------------+
|  1 | K8s version less than v1.24 | kernel version                 | 5.10.104-linuxkit              | critical | Kernel version is suffering    |
|    |                             |                                |                                |          | the CVE-2022-0185 with         |
|    |                             |                                |                                |          | CAP_SYS_ADMIN vulnerablility,  |
|    |                             |                                |                                |          | has a potential container      |
|    |                             |                                |                                |          | escape.                        |
+----+-----------------------------+--------------------------------+--------------------------------+----------+--------------------------------+
|  2 | ClusterRoleBinding          | binding name:                  | verbs:                         | high     | Key permission are given to    |
|    |                             | vuln-clusterrolebinding |      | get,watch,list,create,update | |          | the default service account    |
|    |                             | rolename: vuln-clusterrole |   | resources: pods,services       |          | which will cause a potential   |
|    |                             | namespace: default             |                                |          | container escape.              |
+----+-----------------------------+--------------------------------+--------------------------------+----------+--------------------------------+
```

## Checklist

> Docker

| Supported | Check Item            | Description                                                                              | Severity                 |
|-----------|-----------------------|------------------------------------------------------------------------------------------|--------------------------|
| ✔         | PrivilegeAllowed      | Privileged module is allowed.                                                            | critical                 |
| ✔         | Capabilities          | Dangerous capabilities are opening.                                                      | critical                 |
| ✔         | Volume Mount          | Mount dangerous location.                                                                | critical                 |
| ✔         | Docker Unauthorized   | 2375 port is opening and unauthorized.                                                   | critical                 |
| ✔         | Kernel version        | Kernel version is under the escape version.                                              | critical                 |
| ✔         | Network Module        | Net Module is `host` and containerd version less than 1.41.                              | critical                 |
| ✔         | Docker Server version | Server version is included the vulnerable version                                        | critical/high/medium/low |
| ✔         | Image tag check       | Image is not tagged or `latest`.                                                         | low                      |
| Pending   | docker-compose        | Some dangerous configuration.                                                            | -                        |
| Pending   | Container env         | Check Unauthorized database and weak password, such as `MySQL`, `Redis`, `Memcache` etc. | -                        | 

---


> Kubernetes

| Supported | Check Item                                             | Description                                                  | Severity                |
|-----------|--------------------------------------------------------|--------------------------------------------------------------|-------------------------|
| ✔         | PrivilegeAllowed                                       | Privileged module is allowed.                                | critical                |
| ✔         | Capabilities                                           | Dangerous capabilities are opening.                          | critical                |
| ✔         | PV and PVC                                             | PV is mounted the dangerous location and is actived.         | critical/medium         |
| ✔         | ClusterRoleBinding                                     | Permissions with default server account.                     | high/medium             |
| ✔         | Kubernetes-dashborad                                   | Checking `-enable-skip-login` and account permission.        | critical/high/low       |
| ✔         | Kernel version (k8s verions is less than v1.24)        | Kernel version is under the escape version.                  | critical                |
| ✔         | Docker Server version  (k8s verions is less than v1.24) | Server version is included the vulnerable version            | critical/high/medium/low |
| ✔         | Kubernetes certification expiration                    | Certification is expired after 30 days.                      | medium                  |
| ✔         | Auto Mount ServiceAccount Token                        | Mounting `/var/run/secrets/kubernetes.io/serviceaccount/token`. | low                     |
| ✔         | NoResourceLimits                                       | No resource limits are set.                                  | low                     |
| ✔         | Job and Cronjob                                        | No seccomp or seLinux are set in Job or CronJob.             | low                     |
| Pending   | CVE-2022-29179                                         | CVE-2022-29179 with cilium installed                                                             | critical                |
| Pending   | Envoy admin                                            | Envoy admin is opening and listen to `0.0.0.0`.              | -                       |
| Pending   | Kubelet 10255 and Kubectl proxy                        | 10255 port is opening or Kubectl proxy is opening.           | -                       |
| Pending   | Trampoline attack                                      | RBAC is vulnerable to Trampoline attack.                     | -                       |


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
  upgrade     Upgrade vulnerability database
  version     Print version information and quit

Flags:
  -h, --help   help for vesta

```



