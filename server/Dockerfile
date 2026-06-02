# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go SQLite (modernc) → CGO can be disabled for a static, distroless-ready binary.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# --- runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
EXPOSE 8080
# DB lives on a writable mounted volume (PVC); root FS stays read-only.
ENV DB_PATH=/data/digest.db
USER nonroot:nonroot
ENTRYPOINT ["/server"]
