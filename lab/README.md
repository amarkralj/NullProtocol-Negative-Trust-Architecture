# Isolated attack lab

Everything here runs **inside a virtual machine** (Ubuntu Server 24.04 ARM in UTM on the Mac), never on the host.
The attacks only target the VM's own Kubernetes cluster; with the VM on a host-only network they never reach the internet.

| Step | Where | What |
|---|---|---|
| 1 | Mac | UTM VM: 4 CPU, 6 GB RAM, 25 GB disk, no shared folders, no clipboard sharing, network "Shared" for setup only |
| 2 | VM | `sudo bash provision.sh` (Docker, kind, kubectl, a cluster with full API audit logging) |
| 3 | Mac | UTM: take a snapshot "clean", then switch the network to **Host Only** (no internet from here on) |
| 4 | VM | `bash scenarios/k8s.sh` (labelled attacks and ordinary admin work; writes `labels.jsonl`) |
| 5 | VM | `bash collect.sh` (one tarball: API audit log + labels) |
| 6 | Mac | copy the tarball out (`scp`), then restore the "clean" snapshot |

The labels are written by the scenario script itself, step by step, before the detection engine sees anything; the
engine's rules were not written for these logs. That makes every run a fresh blind test with real Kubernetes API
server logs, and the ordinary steps measure false alarms.
