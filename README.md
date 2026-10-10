# cloudingfy

On-demand HTTPS proxy on [Clouding.io](https://clouding.io), driven by their API.

One command creates a minimal Debian 13 VM running [Squid](http://www.squid-cache.org/)
with TLS and basic authentication; another one destroys it. A third one prints a script that
points `apt`, the Docker daemon and your shell at it.

It was built to work around IP blocks in Spain that break access to Cloudflare-hosted
services such as Docker Hub: egress traffic goes out through a VM in a different network.

## Requirements

- `bash`, `curl`, `jq`, `openssl` on the machine running the script.
- A Clouding.io account and an API key.
- Optional: at least one SSH key uploaded to Clouding if you want shell access to the VM.

## Setup

```sh
cp .api.sample .api                 # put your Clouding API key in it (the key only, no newline needed)
cp proxy.conf.sample proxy.conf     # set USER=... and PASSWORD=...
```

`proxy.conf` is parsed, never sourced, so characters such as `$`, `%` or `?` in the password
are fine. Values may be quoted or not. Quotes, backslashes, whitespace (and `:` in `USER`) are
rejected. Both `.api` and `proxy.conf` are git-ignored, as are the local `.state` and
`.proxy-cert.pem` files.

## Usage

```sh
./cloudingfy.sh cost                       # price per hour/month, creates nothing
./cloudingfy.sh keys                       # list your Clouding SSH keys
./cloudingfy.sh up [--key ID|NAME]         # create firewall + server, wait until the proxy answers
./cloudingfy.sh status
./cloudingfy.sh curl https://ifconfig.me   # curl through the proxy
./cloudingfy.sh generate | sudo bash       # configure this machine (see below)
./cloudingfy.sh generate --remove | sudo bash
./cloudingfy.sh down                       # delete server and firewall
```

`up` takes about two minutes. If `--key` (or `SSH_KEY`) is not given, it lists your SSH keys
and asks which one to enable; answering with Enter creates the VM with no SSH access at all.

Environment variables: `FLAVOR` (default `0.5x1`, about 0.004 EUR/h), `IMAGE_ID` (Debian 13),
`DISK_GB` (`5`), `SSH_FROM` (CIDR allowed on 22/tcp, default `0.0.0.0/0`).

### `generate`

Prints a self-contained script. Run it as root (`| sudo bash`); it is idempotent.

| What                    | Where                                                  |
|-------------------------|--------------------------------------------------------|
| Trusts the proxy cert   | `/usr/local/share/ca-certificates/cloudingfy-proxy.crt` |
| Maps the proxy name     | a tagged line in `/etc/hosts`                          |
| `apt`                   | `/etc/apt/apt.conf.d/01cloudingfy-proxy` (mode 600)    |
| Docker daemon (pulls)   | systemd drop-in `docker.service.d/10-cloudingfy-proxy.conf` |
| Shell                   | tagged block in the invoking user's `~/.bashrc`        |

The Docker daemon is restarted only if no containers are running; otherwise you get a warning.
This covers image pulls. It does **not** proxy traffic generated inside containers (for example
a `RUN apt-get` in a `docker build`).

## How it works

1. `up` creates a firewall (3142/tcp, plus 22/tcp only if an SSH key was selected) and a server
   from the Debian image, with the provisioning script passed as `userData` (cloud-init).
2. A self-signed EC certificate is generated **locally**. The server's IP does not exist yet,
   so its SAN is the fixed name `proxy.cloudingfy.lan`; `generate` maps that name to the IP.
   `./cloudingfy.sh curl` pins the public key instead and needs none of that.
3. Squid listens only with TLS (`https_port 3142`, no plaintext port). Access requires basic
   auth; the password reaches the VM only as an `apr1` hash. Destinations on loopback and
   link-local ranges are denied.
4. With an SSH key selected, only that key is installed and `sshd` is set to key-only.
5. If creating the server fails, the freshly created firewall is removed again.

## Security notes

- The proxy certificate private key and the password hash are stored in the VM's `userData`
  (visible in the Clouding panel/API) and on its disk.
- `generate` writes the proxy password in clear text in `~/.bashrc` and in the apt and Docker
  configuration of the client machine.
- The proxy port is open to the whole Internet (the client IP is not known in advance); basic
  auth over TLS is the only barrier. Tighten the firewall rule if your IP is stable.
- `wget` does not support HTTPS proxies and will not use this setup.

## Notes on the Clouding API

- OpenAPI spec: `https://api.clouding.io/swagger/v1/swagger.json`, auth via the `X-API-KEY` header.
- The API sits behind a WAF that returns `403` for some request bodies. The literal absolute
  path of the sshd main config file inside `userData` is one of them (false positive); the
  provisioning script therefore uses `cd` plus a relative path. A request body can be checked
  without creating anything by posting it to `/v1/servers/cost`: `400` means it got through.

## Status

Verified end to end against Clouding: `up`, proxying with `curl`, a Docker daemon pulling and
running an image through the proxy, `down`. The generated client script was exercised on a
clean Debian 13 container (apt, shell variables, `--remove`). The systemd drop-in was validated
with `systemd-analyze` but not applied to a real host, and the interactive key prompt was only
tested non-interactively.
