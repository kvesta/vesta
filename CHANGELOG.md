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
