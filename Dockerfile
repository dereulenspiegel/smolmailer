FROM scratch
COPY smolmailer /
ENTRYPOINT ["/smolmailer"]
