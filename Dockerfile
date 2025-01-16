FROM alpine:latest as ca-builder
RUN apk --no-cache add ca-certificates && update-ca-certificates

FROM scratch
COPY --from=ca-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY smolmailer /
ENTRYPOINT ["/smolmailer"]
