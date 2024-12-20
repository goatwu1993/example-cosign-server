# example-cosign-server

example-cosign-server

```bash
make keys
make run
```

another shell

```bash
cosign generate ttl.sh/91ec96fe-f5db-44c8-9745-b20a12e3d903@sha256:3389728c430489c997982ca269bbee932889223ba54779052a8134dd793ef4bd > payload.json
export BASE64_PAYLOAD=$(base64 -w 0 payload.json)
curl -X POST -H "Authorization: ${GITHUB_OIDC_TOKEN}" \
     -H "Content-Type: application/json" \
     -d "{\"payload\": \"${BASE64_PAYLOAD}\"}" \
     http://localhost:8000/api/v1/sign
```
