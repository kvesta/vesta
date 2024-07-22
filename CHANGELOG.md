# 1.0.11 (2024.7.22)
## improvements
- Add adaptive scanning for image scanning after Docker Version 25.0.0

# 1.0.10 (2024.2.2)
## features
- Add checking of `CVE-2024-21626`
- Add checking of `CVE-2024-3094` liblzma.so backdoor

## improvements
- Add the severity of each Linux capabilities

# 1.0.9 (2023.8.8)
## features
- Add account checking in `/etc/passwd`
- Add filesystem scanning
- Add checking of ingress nginx
- Add BearerToken for authentication
- Add insecure and server flags in k8s analysis
- Add environment checking in docker images

## improvements
- Add the counter of each severity 
- Add some rules of annotation checking
- Delete the inside flag due to duplicate
- Add `.dockerconfigjson` in secret checking
- Add Docker Histories environment checking
- Add the date of kernel compiling checking in checking of kernel version
- Add the error output in image saving

## fixed
- Fix the out of range in container extract


# 1.0.8 (2023.6.6)
## features
- Add dangerous image used checking in Docker
- Add Docker Swarm Service checking
- Add checking of ephemeral-storage usage

## improvements
- Annotate the tag of image checking

## improvements
- Add unauthorized kubelet checking for each node
- Add support of k3s and k0s

## fixed
- fix the error of compared version
- fix the error of parameter input in file scan

# 1.0.7 (2023.4.1)
## features
- Add trampoline attacking check
- Add malicious value checking in docker history
- Add source `OSCS` for malware checking
- Add Windows path Volume checking

# 1.0.6 (2023.3.2)
## features
- Add Kubernetes `DaemonSet` checking
- Add rootkit and backdoor checking in K8s and Docker
- Add k8s version checking
- Add k8s `PodSecurityPolicy` checking for k8s version under the v1.25

## improvements
- Add some rules for CAP checking
- Change the namespace checking of Secret and ConfigMap
- Improve the rules of `DeamonSet` scanning
- Change the scan rules of `Job` and `CronJob`
- Optimize the method of annotation checking

## fixed
- fix the comparison of kernel version
- fix the errors of base64 decode

# 1.0.5 (2023.2.13)
## features
- Add Docker `--pid=host` checking
- Add Python pip analysis from poetry and venv

## improvements
- Change the minimum of downloaded vulnerable data year from 2002 to 2010
- Parse the env command in Docker Histories
- Rewrite method of java libraries, especially log4j
- Change the format of output of image scan

# 1.0.4 (2023.1.16)
## features
- Add sidecar Environment Checking, including `Env` and `EnvFrom`
- Add pip name checking, detect whether package is potential malware
- Add pod annotation checking

## improvements
- Change method of rpm analysis
- Change folder structure
- Change method of kernel version checking
- Change command `upgrade` to `update`

# 1.0.3 (2023.1.3)
## features
- Add java libraries analysis
- Add php libraries analysis
- Add rust libraries analysis
- Add istio checking
- Add Docker history analysis

## improvements
- Change the method of npm analysis
- Add mount filesystem for container scan
- Change method of cilium checking
- Change the method of image scanning
- Add RBAC User output for untrusted User checking
- Revise the rules of RBAC checking

## fixed
- Fixed error of version comparison

# 1.0.2 (2022.12.24)
## features
- Add cilium checking
- Add Kubelet `read-only-port` and `kubectl proxy` checking 
- Add Etcd safe configuration checking
- Add RoleBinding checking
- Optimize layer integration
- Add go binary analysis

# 1.0.1 (2022.12.13)
## features
- Add weak password checking in Configmap and Secret
- Add weak password checking in Docker env
- Add `--skip` parameter for image or container scanning
- Add Envoy admin checking

# 1.0.0 (2022.12.4)
## features
- Image or Container scan
- Docker configuration scan
- Kubernetes configuration scan
