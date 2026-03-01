# 🐳 Dockerfile Best Practices

## 1. Use a `.dockerignore` File
- Exclude unnecessary files to keep builds clean and fast.
- Prevent accidental leakage of sensitive data.
- Significantly reduce build context size.

**Always ignore things like:**
```
.git
node_modules
.env
*.log
dist
```

✅ Smaller context → faster builds + safer images.

---

## 2. Clean Up in the Same Layer
- Never leave package manager cache in the final image.
- Combine install and cleanup in **one RUN**.

✅ Good
```dockerfile
RUN apt-get update && apt-get install -y curl  && rm -rf /var/lib/apt/lists/*
```

❌ Bad
```dockerfile
RUN apt-get update
RUN apt-get install -y curl
RUN rm -rf /var/lib/apt/lists/*
```

---

## 3. Don’t Use `ENV` for Secrets
- `ENV` values are visible via **docker inspect**.
- Never bake secrets into images.

✅ Use `ARG` for build-time only
```dockerfile
ARG BUILD_VERSION
```

✅ Use runtime secrets (Docker/Kubernetes secrets or mounted volumes).

---

## 4. Run as a Non-Root User
Running as root is a major security risk.

```dockerfile
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
```

---

## 5. Optimize Docker Cache Order

✅ Correct order
```dockerfile
COPY package*.json ./
RUN npm install
COPY . .
```

❌ Wrong order
```dockerfile
COPY . .
RUN npm install
```

---

## 6. Pin Your Versions

❌ Bad
```dockerfile
FROM node:latest
```

✅ Good
```dockerfile
FROM node:20-alpine
```

---

## 7. Use Minimal Base Images
Prefer:
- alpine
- *-slim
- distroless

Benefits:
- Smaller image size
- Faster pulls
- Smaller attack surface

---

## 8. Use Multi-Stage Builds

```dockerfile
# ---- build stage ----
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# ---- runtime stage ----
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
CMD ["node", "dist/index.js"]
```

---

## 9. Add a HEALTHCHECK

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s   CMD curl -f http://localhost:8080 || exit 1
```

---

## 10. Combine RUN Instructions

✅ Good
```dockerfile
RUN apk add --no-cache curl bash  && mkdir /app  && chown -R appuser:appgroup /app
```

❌ Bad
```dockerfile
RUN apk add curl
RUN apk add bash
RUN mkdir /app
```

---

# 🔥 Bonus Tips

## Use `--no-cache` with Alpine
```dockerfile
RUN apk add --no-cache curl
```

## Set a Working Directory Early
```dockerfile
WORKDIR /app
```

## Prefer Exec Form for CMD
```dockerfile
CMD ["node", "server.js"]
```

---

# ✅ Quick Checklist

- [ ] Using `.dockerignore`
- [ ] No secrets in image
- [ ] Running as non-root
- [ ] Minimal base image
- [ ] Versions pinned
- [ ] Multi-stage build used
- [ ] Layers optimized
- [ ] HEALTHCHECK added
- [ ] Cache order optimized
