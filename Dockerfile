FROM golang:1.24-alpine AS builder
RUN apk --no-cache add ca-certificates build-base && update-ca-certificates
RUN mkdir /work
WORKDIR /work
COPY . .
RUN make dist/smolmailer_native
RUN ldd dist/smolmailer_native | tr -s [:blank:] '\n' | grep ^/ | xargs -I % install -D % /work/dist/%
RUN ln -s ld-musl-$(uname -i).so.1 /work/dist/lib/libc.musl-$(uname -i).so.1

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /work/dist /
ENTRYPOINT ["/smolmailer_native"]
