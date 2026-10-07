# Running claw-wrap as a Kubernetes sidecar

This guide runs claw-wrap next to an AI agent in one pod. The agent container holds no secrets. It calls wrapped tools through the claw-wrap client, and the sidecar runs the real binaries with credentials injected.

```
Pod
├─ agent       /usr/local/bin/<tool> -> claw-wrap (client only, no secrets)
│                 │  Unix socket + HMAC on a shared emptyDir
└─ claw-wrap   daemon: UID check, HMAC, argument allowlist, audit
   (sidecar)      └─ runs the real <tool> with credentials from a Secret
```

Only CLI brokering is used here. The HTTP proxy stays off.

A working manifest is in [`examples/kubernetes/deployment.yaml`](../examples/kubernetes/deployment.yaml), with a matching tool config in [`examples/mcparcel/wrappers.yaml`](../examples/mcparcel/wrappers.yaml). Both were deployed to a kind cluster (Kubernetes 1.35) and exercised end to end while writing this guide.

## Images

### Sidecar

The repository `Dockerfile` builds a small Debian image with `claw-wrap`, `tini` and CA certificates. It runs as UID/GID 10001 with `claw-wrap daemon` as the default command and `tini` as PID 1.

Add the tools you want to broker in a derived image:

```dockerfile
FROM ghcr.io/dedene/claw-wrap:0.6.0
COPY --from=mytool-build /out/mcparcel /usr/local/bin/mcparcel
```

`tini` matters when a wrapped tool starts a background daemon: once the tool exits, the daemon is reparented to PID 1, and `tini` reaps it when it dies. Without an init process it lingers as a zombie, and a liveness check like `kill -0 <pid>` keeps reporting it as alive.

### Agent

The agent image needs the `claw-wrap` binary and one symlink per tool. The symlink name is the tool name claw-wrap asks the daemon for.

```dockerfile
COPY --from=ghcr.io/dedene/claw-wrap:0.6.0 /usr/local/bin/claw-wrap /usr/local/bin/claw-wrap
RUN ln -s claw-wrap /usr/local/bin/mcparcel
```

Release archives with linux/amd64 and linux/arm64 binaries work too.

## Shared runtime directory

The client and daemon find each other through the runtime directory: `secrets.sock` (the Unix socket) and `auth` (the HMAC secret the client signs requests with). Both containers mount the same `emptyDir` and set the same `CLAW_WRAP_RUNTIME_DIR`:

```yaml
env:
  - name: CLAW_WRAP_RUNTIME_DIR
    value: /run/claw-wrap/ipc
volumeMounts:
  - name: ipc
    mountPath: /run/claw-wrap
```

Point `CLAW_WRAP_RUNTIME_DIR` at a subdirectory of the mount, not at the mount itself. The kubelet creates `emptyDir` mounts owned by root, so the non-root daemon cannot chmod them. It creates the subdirectory itself and controls its mode.

`CLAW_WRAP_RUNTIME_DIR` only moves the socket, the auth file and the proxy auth token. The `env:` credential file stays at its default location, because the runtime directory here is shared with the agent.

## Users, groups and modes

The example runs the sidecar as UID 10001 and the agent as UID 1000, with `fsGroup: 2000` on the pod. Every container gets GID 2000 as a supplementary group, and the kubelet gives that group to the `emptyDir` and Secret volumes.

```yaml
args: [daemon, --uid, "1000", --runtime-gid, "2000", --socket-mode, "0660", --auth-mode, "0640"]
```

| Flag | Effect |
| --- | --- |
| `--uid 1000` | Only peers with UID 1000 (the agent) are accepted. Everything else is rejected before HMAC is checked. |
| `--runtime-gid 2000` | Runtime dir becomes `0750`, socket and auth file are chgrp'd to 2000. |
| `--socket-mode 0660` | Group members can connect. Allowed: `0600`, `0660`. |
| `--auth-mode 0640` | Group members can read the HMAC secret. Allowed: `0600`, `0640`. |

Resulting layout as seen from the agent:

```
drwxr-x--- 10001 2000 /run/claw-wrap/ipc
-rw-r----- 10001 2000 /run/claw-wrap/ipc/auth
srw-rw---- 10001 2000 /run/claw-wrap/ipc/secrets.sock
```

Running both containers as the same UID also works, with the default `0600` modes and no `--runtime-gid`. Separate UIDs are the safer default: if someone later turns on `shareProcessNamespace`, the agent still cannot read the sidecar's `/proc/<pid>/environ`.

## Security model

Keep `shareProcessNamespace: false`. The agent must not see the sidecar's processes.

The consequence is that claw-wrap cannot verify the caller's executable. Across PID namespaces `SO_PEERCRED` reports PID 0, so `/proc/<pid>/exe` is not available. The daemon logs this once:

```
[INFO] caller executable cannot be verified (peer pid=0, e.g. a separate PID namespace); requests are authorized by UID + HMAC only
```

Leave `security.deny_unverified_caller_exe` at `false`; with `true` every request is rejected.

What protects the tools then:

1. Only containers that mount the `ipc` volume can reach the socket at all.
2. The peer UID must equal `--uid`.
3. Requests must be signed with the HMAC secret from the auth file and are replay-protected.
4. Arguments must pass the tool's `blocked_args` and `allowed_args`.
   The caller's environment and working directory are ignored when the tool sets `request_env: []` and `working_dir`.
5. The tool itself may enforce its own policy (mcparcel's `toolPolicy`, for example).

Points 2 and 3 identify "a process in the agent container", nothing finer. The agent holds the HMAC secret, so it can sign any request it likes: arguments, environment, working directory. For every tool in a sidecar:

- Use `mode: allowlist` with `match: argv` rules; see [CONFIG.md](CONFIG.md#allowed_args-optional-requires-mode-allowlist).
- Set `request_env: []` (or a short list like `[TERM]`). Otherwise the agent can pass tool-specific variables, for example a config path or server URL that redirects the credentials.
- Set `working_dir`. Otherwise the tool runs in a directory the agent picks, which matters as soon as the sidecar shares a volume with the agent (think `.git/config` or `.npmrc` in an agent-writable workspace).

Also set `automountServiceAccountToken: false` unless the agent needs the Kubernetes API.

## Secrets

Mount the Secret into the sidecar only, and read it with the `file:` credential backend:

```yaml
credentials:
  front_client_secret:
    source: file:/etc/claw-wrap/secrets/front-client-secret
```

```yaml
volumes:
  - name: secrets
    secret:
      secretName: claw-wrap-secrets
      defaultMode: 0440
```

Secret volume files are root-owned symlinks into a `..data` directory. `file:` follows symlinks and accepts files owned by root or the daemon UID, as long as they are not group-writable and not accessible by others. With `fsGroup` and `defaultMode: 0440` the files are `root:2000 0440`, readable by the sidecar. The agent is also in group 2000 but does not mount the volume.

`file:` is read on every use, so rotated Secrets apply on the next call after the kubelet updates the volume.

Map credentials to fixed env names with `env:`. claw-wrap redacts every injected credential value of 8 bytes or more from the tool's stdout and stderr. That only catches the exact value; an encoded copy gets through, so do not rely on it as the only control. The audit log never contains environment variables.

## Config and hot reload

Mount `wrappers.yaml` from a ConfigMap at `/etc/openclaw` (the default config path). Mount the whole ConfigMap, not a `subPath`: subPath mounts never receive updates.

The kubelet updates ConfigMap volumes by swapping a `..data` symlink. claw-wrap watches for that swap and reloads, typically within a minute of `kubectl apply`. An invalid config is rejected and the previous one stays active.

## Probes

Use a startup probe and a readiness probe that check for the socket and auth file:

```yaml
startupProbe:
  exec:
    command: ["sh", "-c", "test -S /run/claw-wrap/ipc/secrets.sock && test -s /run/claw-wrap/ipc/auth"]
  periodSeconds: 1
  failureThreshold: 30
```

As a native sidecar (`initContainers` with `restartPolicy: Always`, Kubernetes 1.29+), the agent container only starts after the sidecar's startup probe passes. On older clusters run claw-wrap as a regular container and let the agent retry until the socket exists.

## Audit log

```yaml
audit:
  enabled: true
  stdout: true
  include_args: true
```

`stdout: true` writes one JSON object per call to the daemon's stdout. Daemon logs go to stderr, so a log pipeline can tell them apart. To keep a file instead, set `file:` to a path on a volume. `/dev/stdout` does not work there because the file logger refuses symlinks.

## Writable paths

With `readOnlyRootFilesystem: true` the sidecar needs:

| Path | Why |
| --- | --- |
| `/run/claw-wrap` | Shared `ipc` emptyDir |
| `/tmp` | Large-output buffering and `config_file` temp dirs |
| `/var/lib/claw-wrap` | `HOME` and the tool's `working_dir`: tool state such as a daemon socket or token cache |

## Tools that start a background daemon

Some CLIs start a long-lived daemon on first use and talk to it afterwards. claw-wrap supports this when the daemon detaches properly:

- Start it in a new session (`setsid`). claw-wrap runs each tool in its own process group and kills that group when the call ends, so a daemon left in the group dies with it.
- Point its stdin, stdout and stderr at `/dev/null` or a log file. If it keeps the tool's stdout or stderr open, claw-wrap stops reading one second after the tool exits, logs a warning and returns. The daemon then writes into a closed pipe, which kills most runtimes with `SIGPIPE`.

The daemon inherits the tool's environment, including credentials from `env:`. Its state lives in the sidecar's filesystem (`HOME`, `working_dir`) and is never visible to the agent.

## Non-interactive tools

Set `use_stdin: false` on tools the agent calls. The tool reads from `/dev/null`, so a prompt fails immediately instead of waiting for input until `timeout` expires. It also turns off PTY mode. Without it, a tool that waits on stdin is killed at its `timeout` (SIGTERM, then SIGKILL after 5 seconds).

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `connect: no such file or directory` in the agent | `CLAW_WRAP_RUNTIME_DIR` differs between containers, or the sidecar is not up yet |
| `load secret: ... permission denied` | Agent not in the runtime group: check `fsGroup`, `--runtime-gid`, `--auth-mode 0640` |
| `unauthorized caller` | Agent UID does not match `--uid` |
| `invalid working directory` | The caller's cwd does not exist in the sidecar. Set `working_dir` on the tool. |
| Tool ignores a variable the agent sets | Expected with `request_env: []`; list the variable if the tool really needs it |
| `unknown tool` | No `tools:` entry with that name; the daemon also warns at startup when `tools` is empty |
| `chmod runtime dir: operation not permitted` | `CLAW_WRAP_RUNTIME_DIR` points at the emptyDir mount itself; use a subdirectory |
| Config changes not picked up | ConfigMap mounted with `subPath` |
