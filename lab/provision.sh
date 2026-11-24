#!/usr/bin/env bash
# Inside the lab VM only. Installs Docker, kind and kubectl and starts a cluster whose API server writes a full audit log.
set -euo pipefail
[ -f /etc/os-release ] && grep -q Ubuntu /etc/os-release || { echo "run this inside the Ubuntu lab VM"; exit 1; }
apt-get update -y && apt-get install -y docker.io curl jq
ARCH=arm64; KIND=v0.24.0; KUBECTL=v1.31.2
curl -fsSLo /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/${KIND}/kind-linux-${ARCH}" && chmod +x /usr/local/bin/kind
curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL}/bin/linux/${ARCH}/kubectl" && chmod +x /usr/local/bin/kubectl
mkdir -p /opt/lab/audit
cat > /opt/lab/audit-policy.yaml <<'POL'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: None
    users: ["system:kube-proxy"]
  - level: RequestResponse
    resources: [{group: "", resources: ["pods", "pods/exec", "secrets", "serviceaccounts/token", "services"]},
                {group: "rbac.authorization.k8s.io"}, {group: "apps"}, {group: "batch"},
                {group: "admissionregistration.k8s.io"}, {group: "certificates.k8s.io"}]
  - level: Metadata
POL
cat > /opt/lab/kind.yaml <<'CFG'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-log-path: /var/log/kubernetes/audit.log
            audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml
          extraVolumes:
            - {name: audit-policies, hostPath: /etc/kubernetes/policies, mountPath: /etc/kubernetes/policies, readOnly: true, pathType: DirectoryOrCreate}
            - {name: audit-logs, hostPath: /var/log/kubernetes, mountPath: /var/log/kubernetes, readOnly: false, pathType: DirectoryOrCreate}
    extraMounts:
      - {hostPath: /opt/lab/audit-policy.yaml, containerPath: /etc/kubernetes/policies/audit-policy.yaml, readOnly: true}
      - {hostPath: /opt/lab/audit, containerPath: /var/log/kubernetes}
CFG
kind create cluster --name lab --config /opt/lab/kind.yaml
docker pull nginx:1.27 && docker pull busybox:1.36 && kind load docker-image nginx:1.27 busybox:1.36 --name lab
echo "ready: audit log at /opt/lab/audit/audit.log. Snapshot the VM, then switch it to Host Only."
