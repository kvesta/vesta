FROM golang:1.20 as builder
WORKDIR /build
COPY . .
ENV GOOS=linux CGO_ENABLED=1
RUN make build.unix

FROM alpine:3.17.3
WORKDIR /tool
COPY --from=builder /build/vesta .
RUN chmod +x /tool/vesta
ENTRYPOINT ["./vesta"]
