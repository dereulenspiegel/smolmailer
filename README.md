# smolmailer

This is a very simple SMTP server for your homelab. It is not meant as a general purpose
SMTP server. It is meant to deliver notification emails, password reset emails etc. to your users.
It tries to be as simple to setup as possible and to integrate with infrastructure automation tools.

## Features

* Small
* Simple
* DKIM signing
* Simple user management in a simple yaml file
* Automatic ACME management

## Config

Configuration can be done via a YAML config file or environment variables. smolmailer
can have multiple DKIM signer each with their own selector and private key. This can be used
to sign emails with different key types (i.e. RSA and ed25519) at the same time or to do
key roll overs (or both).

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | ---: |
| SMOLMAILER_MAILDOMAIN | Email Domain, used für EHLO etc. | - |
| SMOLMAILER_TLSDOMAIN | Domain for mail senders to connect to, ACME certificates will be acquired for this | - |
| SMOLMAILER_LISTENADDR | The network address to listen on for client connection | [::]:2525 |
| SMOLMAILER_LISTENTLS | Whether to enable TLS for client connections | false |
| SMOLMAILER_LOGLEVEL | The log level | info |
| SMOLMAILER_SENDADDR | The IP address to send emails from. Needs to assigned to an available network interface | - |
| SMOLMAILER_QUEUEPATH | The directory where the persited queue is stored | /data/qeues |
| SMOLMAILER_USERFILE | The file where the users are configured | /config/users.yaml |
| SMOLMAILER_ALLOWEDIPRANGES | IP ranges which are permitted to connect as clients, all are permitted if nothing is set here | - |
| SMOLMAILER_ACME_DIR | The directory where ACME account, keys, certificates etc. are stored | /data/acme |
| SMOLMAILER_ACME_EMAIL | Email address of the ACME account | - |
| SMOLMAILER_ACME_CAURL | URL of the ACME CA | https://acme-v02.api.letsencrypt.org/directory |
| SMOLMAILER_ACME_RENEWAL_INTERVAL | Interval after which the ACME certificates get renewed | 30d |
| SMOLMAILER_ACME_DNS01_PROVIDERNAME | Provider name of the lego DNS01 provider | - |
| SMOLMAILER_ACME_DNS01_DONTWAITFORPROPAGATION | Whether to wait for DNS solution propagation | false |
| SMOLMAILER_ACME_DNS01_PROPAGATIONTIMEOUT | Timeout to wait for propagation of DNS solution records | 5m |
| SMOLMAILER_ACME_DNS01_DEFAULTHOSTNAME | Default hostname to always acquire a certificate for | - |
| SMOLMAILER_DKIM_SIGNER_{signer name}_SELECTOR | DKIM selector name for this DKIM signer | - |
| SMOLMAILER_DKIM_SIGNER_{signer name}_PRIVATEKEY_KEY | PEM encoded private key for this DKIM signer, takes precedence over PATH | - |
| SMOLMAILER_DKIM_SIGNER_{signer name}_PRIVATEKEY_PATH | PEM encoded file of the private key for this DKIM signer | - |

### YAML config

Example:

```yaml
QueuePath: ./data/qeues
ListenTls: false
TlsDomain: "smtp.example.com"
MailDomain: "example.com"
ListenAddr: "[::]:1234"
LogLevel: debug
SendAddr: fdb1:0113:82fa::1
UserFile: /config/users.yaml
AllowedIPRanges: ["fdb1:0113:82fa::/64"]
Acme:
  CAUrl: https://acme-staging-v02.api.letsencrypt.org/directory
  Email: admin@example.com
  DNS01ProviderName: exec
  Dir: ./data/acme
Dkim:
  Signer:
    RSA:
      Selector: example-rsa
      PrivateKey:
        Path: /config/dkim/rsa.key
```
