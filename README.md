<p align="center" style="text-align: center">
    <img src="https://user-images.githubusercontent.com/35037256/212051309-56468d85-4132-4780-9722-d1c0dcc79b1b.png" width="55%">
<br/>
</p>

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
|    |                                | sidecar name: vulntest |       | memory, cpu, ephemeral-storage | Pod                   | low      | None of resources is be        |
|    |                                | Resource                       |                                |                       |          | limited.                       |
|    |                                |                                |                                |                       |          |                                |
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

## Checklist

> Docker

| Supported | Check Item                | Description                                                              | Severity                 |
|-----------|---------------------------|--------------------------------------------------------------------------|--------------------------|
| ✔         | PrivilegeAllowed          | Privileged module is allowed.                                            | critical                 |
| ✔         | Capabilities              | Dangerous capabilities are opening.                                      | critical                 |
| ✔         | Volume Mount              | Mount dangerous location.                                                | critical                 |
| ✔         | Docker Unauthorized       | 2375 port is opening and unauthorized.                                   | critical                 |
| ✔         | Kernel version            | Kernel version is under the escape version.                              | critical                 |
| ✔         | Network Module            | Net Module is `host` and containerd version less than 1.41.              | critical                 |
| ✔         | Docker Server version     | Server version is included the vulnerable version                        | critical/high/medium/low |
| ✔         | Docker env password check | Check weak password in database.                                         | high/medium              |
| ✔         | Image tag check           | Image is not tagged or `latest`.                                         | low                      |
| ✔         | Docker History            | Docker layers have some  dangerous commands.                             | high/medium              |
| Pending   | IaC scan                  | IaC scan.                                                                | -                        |

---


> Kubernetes

| Supported | Check Item                                              | Description                                                                | Severity                 |
|-----------|---------------------------------------------------------|----------------------------------------------------------------------------|--------------------------|
| ✔         | PrivilegeAllowed                                        | Privileged module is allowed.                                              | critical                 |
| ✔         | Capabilities                                            | Dangerous capabilities are opening.                                        | critical                 |
| ✔         | PV and PVC                                              | PV is mounted the dangerous location and is actived.                       | critical/medium          |
| ✔         | RBAC                                                    | RBAC has some unsafe configurations in clusterrolebingding or rolebinding. | high/medium/warning      |
| ✔         | Kubernetes-dashborad                                    | Checking `-enable-skip-login` and account permission.                      | critical/high/low        |
| ✔         | Kernel version (k8s versions is less than v1.24)        | Kernel version is under the escape version.                                | critical                 |
| ✔         | Docker Server version  (k8s versions is less than v1.24) | Server version is included the vulnerable version.                         | critical/high/medium/low |
| ✔         | Kubernetes certification expiration                     | Certification is expired after 30 days.                                    | medium                   |
| ✔         | ConfigMap and Secret check                              | Check weak password in ConfigMap or Secret.                                | high/medium              |
| ✔         | Auto Mount ServiceAccount Token                         | Mounting `/var/run/secrets/kubernetes.io/serviceaccount/token`.            | low                      |
| ✔         | NoResourceLimits                                        | No resource limits are set.                                                | low                      |
| ✔         | Job and Cronjob                                         | No seccomp or seLinux are set in Job or CronJob.                           | low                      |
| ✔         | Envoy admin                                             | Envoy admin is opening and listen to `0.0.0.0`.                            | high/medium              |
| ✔         | Cilium version                                          | Cilium has vulnerable version.                                             | critical/high/medium/low |
| ✔         | Istio configurations                                    | Istio has vulnerable version and vulnerable configurations.                | critical/high/medium/low |
| ✔         | Kubelet 10255 and Kubectl proxy                         | 10255 port is opening or Kubectl proxy is opening.                         | high/medium/low          |
| ✔         | Etcd configuration                                      | Etcd safe configuration checking.                                          | high/medium              |
| ✔         | Sidecar configurations                                  | Sidecar has some dangerous configurations.                                 | critical/high/low        |
| Pending   | IaC scan                                                | IaC scan.                                                                  | -                        |


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



