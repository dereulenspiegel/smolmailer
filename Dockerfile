FROM golang:1.24-alpine AS builder
RUN apk --no-cache add ca-certificates build-base && update-ca-certificates
RUN mkdir /work
WORKDIR /work
COPY . .
RUN make dist/smolmailer_native && mv dist/dist/smolmailer_native dist/smolmailer
RUN ldd dist/smolmailer_native | tr -s [:blank:] '\n' | grep ^/ | xargs -I % install -D % /dist/%
#RUN ln -s ../ld-musl-x86_64.so.1 /dist/lib/libc.musl-x86_64.so.1

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /work/dist /
ENTRYPOINT ["/smolmailer"]
