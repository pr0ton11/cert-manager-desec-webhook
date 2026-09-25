FROM golang:1.27.1-alpine AS build

WORKDIR /workspace

COPY . .

RUN go mod download

RUN CGO_ENABLED=0 go build -o webhook .

FROM gcr.io/distroless/static-debian13

COPY --from=build /workspace/webhook /usr/local/bin/webhook

# Run as the distroless nonroot user instead of root.
USER 65532:65532

ENTRYPOINT ["webhook"]
