# RemoteSSL Test Lab

Disposable nginx + sshd target for end-to-end deployment testing (root password: `remotessl`, dev only).

```bash
docker build -t remotessl-lab test-lab/
docker run -d --name remotessl-lab -p 2222:22 -p 8444:443 remotessl-lab
```

Note: containers have no systemd — use `nginx -s reload` as the binding's `reloadCmd`.
