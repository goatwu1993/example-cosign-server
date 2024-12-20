# example-cosign-server

example-cosign-server

```bash
make keys
make run
```

another shell

```bash
curl -X POST -H "Authorization: ${GITHUB_OIDC_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"payload":"eyJjcml0aWNhbCI6eyJpZGVudGl0eSI6eyJkb2NrZXItcmVmZXJlbmNlIjoidHRsLnNoLzkxZWM5NmZlLWY1ZGItNDRjOC05NzQ1LWIyMGExMmUzZDkwMyJ9LCJpbWFnZSI6eyJkb2NrZXItbWFuaWZlc3QtZGlnZXN0Ijoic2hhMjU2OjMzODk3MjhjNDMwNDg5Yzk5Nzk4MmNhMjY5YmJlZTkzMjg4OTIyM2JhNTQ3NzkwNTJhODEzNGRkNzkzZWY0YmQifSwidHlwZSI6ImNvc2lnbiBjb250YWluZXIgaW1hZ2Ugc2lnbmF0dXJlIn0sIm9wdGlvbmFsIjpudWxsfQ=="}' \
     http://localhost:8000/api/v1/sign
```
