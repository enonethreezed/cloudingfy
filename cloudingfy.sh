#!/usr/bin/env bash
# cloudingfy: levanta bajo demanda un Debian en Clouding con Squid (proxy HTTPS en 3142/tcp, BasicAuth).
#
#   ./cloudingfy.sh cost      calcula el coste/hora sin crear nada
#   ./cloudingfy.sh up [--key ID|NOMBRE]
#                             crea firewall + servidor y espera a que el proxy responda.
#                             Sin --key, enumera tus llaves SSH y pregunta cuál activar (o ninguna)
#   ./cloudingfy.sh keys      lista tus llaves SSH de Clouding (id y nombre)
#   ./cloudingfy.sh status    estado del servidor y del proxy
#   ./cloudingfy.sh down      elimina servidor y firewall
#   ./cloudingfy.sh curl URL  atajo: curl a través del proxy (TLS con la clave pública fijada)
#   ./cloudingfy.sh generate [--remove]
#                             imprime un script para configurar un cliente (apt, ~/.bashrc, CA, /etc/hosts):
#                             ./cloudingfy.sh generate | sudo bash     (--remove lo deshace)
#
# Variables opcionales: FLAVOR (0.5x1), IMAGE_ID (Debian 13), DISK_GB (5),
#                       SSH_FROM (CIDR con acceso a 22/tcp si hay llave; por defecto 0.0.0.0/0)
set -euo pipefail

cd "$(dirname "$0")"
API=https://api.clouding.io/v1
STATE=.state
PORT=3142
PROXY_HOST=proxy.cloudingfy.lan # nombre en el SAN del certificado; generate lo mapea en /etc/hosts
FLAVOR=${FLAVOR:-0.5x1}
IMAGE_ID=${IMAGE_ID:-jG4bZNnE8zKYx7LP} # Debian 13 (64 Bit)
DISK_GB=${DISK_GB:-5}
SSH_FROM=${SSH_FROM:-0.0.0.0/0}

die() { echo "error: $*" >&2; exit 1; }
command -v jq >/dev/null || die "falta jq"
[[ -r .api ]] || die "falta el fichero .api"
[[ -r proxy.conf ]] || die "falta el fichero proxy.conf"
API_KEY=$(tr -d '[:space:]' < .api)

# proxy.conf se parsea, no se hace source: la contraseña puede contener $, `, etc.
# Acepta KEY=valor, KEY="valor" y KEY='valor'.
conf_get() {
  local v
  v=$(sed -n -E "s/^$1=(.*)\$/\1/p" proxy.conf | head -n1 | tr -d '\r')
  v=${v%%[[:space:]]}
  if [[ $v =~ ^\"(.*)\"$ || $v =~ ^\'(.*)\'$ ]]; then v=${BASH_REMATCH[1]}; fi
  printf '%s' "$v"
}
PROXY_USER=$(conf_get USER)
PROXY_PASS=$(conf_get PASSWORD)
[[ -n $PROXY_USER && -n $PROXY_PASS ]] || die 'proxy.conf debe tener USER=... y PASSWORD=...'
[[ $PROXY_USER$PROXY_PASS =~ [\"\'\\[:space:]] ]] && die 'USER/PASSWORD no pueden contener comillas, barras invertidas ni espacios'
[[ $PROXY_USER == *:* ]] && die 'USER no puede contener ":"'

api() { # api METHOD PATH [JSON]  -> cuerpo por stdout; falla con el problem-details si HTTP >= 400
  local method=$1 path=$2 body=${3:-} out code
  local args=(-sS -m 60 -X "$method" -H "X-API-KEY: $API_KEY" -H 'Accept: application/json' -w '\n%{http_code}')
  [[ -n $body ]] && args+=(-H 'Content-Type: application/json' --data "$body")
  out=$(curl "${args[@]}" "$API$path")
  code=${out##*$'\n'}
  out=${out%$'\n'*}
  if ((code >= 400)); then echo "HTTP $code en $method $path: $out" >&2; return 1; fi
  printf '%s' "$out"
}

state_get() { [[ -f $STATE ]] && jq -r ".$1 // empty" "$STATE" || true; }
state_set() { local tmp; tmp=$(jq -c ". + {$1: \"$2\"}" "${STATE}" 2>/dev/null || echo "{\"$1\":\"$2\"}"); echo "$tmp" > "$STATE"; chmod 600 "$STATE"; }

wait_action() { # wait_action ACTION_ID
  local id=$1 st
  while :; do
    st=$(api GET "/actions/$id" | jq -r '.status')
    case $st in
      completed) return 0 ;;
      errored) die "la acción $id falló ($st)" ;;
    esac
    sleep 5
  done
}

# NOTA: no escribir en el userData la ruta absoluta completa del sshd_config: el WAF de la API
# de Clouding la bloquea con 403 (falso positivo); por eso se usa cd + ruta relativa.
# El certificado TLS (y su clave) se generan en local en gen_tls; la contraseña va como hash apr1.
user_data() {
  cat <<EOF
#!/bin/bash
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends squid
cat > /etc/squid/cloudingfy.crt <<'CRT'
$TLS_CERT
CRT
cat > /etc/squid/cloudingfy.key <<'KEY'
$TLS_KEY
KEY
printf '%s\n' '$PROXY_USER:$PROXY_HASH' > /etc/squid/passwd
chown root:proxy /etc/squid/cloudingfy.crt /etc/squid/cloudingfy.key /etc/squid/passwd
chmod 640 /etc/squid/cloudingfy.crt /etc/squid/cloudingfy.key /etc/squid/passwd
cat > /etc/squid/squid.conf <<'CONF'
https_port $PORT tls-cert=/etc/squid/cloudingfy.crt tls-key=/etc/squid/cloudingfy.key
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm cloudingfy
auth_param basic children 5
acl authed proxy_auth REQUIRED
acl blocked_dst dst 127.0.0.0/8 169.254.0.0/16 ::1
http_access deny blocked_dst
http_access allow authed
http_access deny all
cache deny all
cache_mem 8 MB
forwarded_for delete
via off
access_log stdio:/var/log/squid/access.log
coredump_dir /var/spool/squid
CONF
squid -k parse
systemctl enable squid
systemctl restart squid
EOF
  [[ -n $SSH_PUBKEY ]] || return 0
  cat <<EOF
install -d -m 700 /root/.ssh
cat >> /root/.ssh/authorized_keys <<'KEYS'
$SSH_PUBKEY
KEYS
chmod 600 /root/.ssh/authorized_keys
cd /etc/ssh
cat > sshd_config.d/10-cloudingfy.conf <<'SSHD'
PermitRootLogin prohibit-password
PasswordAuthentication no
SSHD
systemctl enable --now ssh
systemctl reload ssh
EOF
}

# Certificado autofirmado generado en local. La IP aún no existe, así que el SAN es un nombre fijo
# ($PROXY_HOST): 'generate' lo mapea en /etc/hosts e instala el cert como de confianza en el cliente.
# 'curl' lo fija por clave pública (--proxy-pinnedpubkey) y no necesita nada de eso.
gen_tls() {
  local d; d=$(mktemp -d)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 90 \
    -subj "/CN=$PROXY_HOST" -addext "subjectAltName=DNS:$PROXY_HOST" -addext "basicConstraints=critical,CA:FALSE" \
    -keyout "$d/key" -out "$d/crt" 2>/dev/null
  TLS_KEY=$(<"$d/key"); TLS_CERT=$(<"$d/crt")
  TLS_PIN=$(openssl x509 -in "$d/crt" -pubkey -noout | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | base64 -w0)
  install -m 600 "$d/crt" .proxy-cert.pem
  rm -rf "$d"
}

proxy_curl() { # proxy_curl IP PIN [args de curl...]
  local ip=$1 pin=$2; shift 2
  curl -s -m 20 --proxy "https://$ip:$PORT" --proxy-insecure --proxy-pinnedpubkey "sha256//$pin" "$@"
}

proxy_check() { # devuelve 0 si el proxy responde 200 autenticado y 407 sin credenciales (por TLS)
  local ip=$1 pin; pin=$(state_get tlsPin)
  local anon auth
  anon=$(proxy_curl "$ip" "$pin" -o /dev/null -w '%{http_code}' http://example.com/ || true)
  auth=$(proxy_curl "$ip" "$pin" -o /dev/null -w '%{http_code}' --proxy-user "$PROXY_USER:$PROXY_PASS" http://example.com/ || true)
  echo "  sin credenciales: HTTP $anon (esperado 407) | con credenciales: HTTP $auth (esperado 200)"
  [[ $anon == 407 && $auth == 200 ]]
}

cmd_cost() {
  api POST /servers/cost "$(jq -nc --arg f "$FLAVOR" --arg img "$IMAGE_ID" --argjson g "$DISK_GB" \
    '{flavorId:$f, volume:{source:"image", id:$img, ssdGb:$g}}')" | jq .
}

select_ssh_key() { # $1 = id|nombre|número (opcional). Rellena SSH_KEY_ID y SSH_PUBKEY (vacíos = sin SSH)
  local want=${1:-} rows id name pub i
  local -a ids=() names=() pubs=()
  SSH_KEY_ID=; SSH_PUBKEY=
  rows=$(api GET '/keypairs?pageSize=200' | jq -r '.values[]? | [.id,.name,.publicKey] | @tsv')
  while IFS=$'\t' read -r id name pub; do
    [[ -n $id ]] || continue
    ids+=("$id"); names+=("$name"); pubs+=("$pub")
  done <<<"$rows"

  echo "Llaves SSH en Clouding:"
  for i in "${!ids[@]}"; do printf '  %d) %s  (%s)\n' "$((i+1))" "${names[i]}" "${ids[i]}"; done
  ((${#ids[@]})) || echo "  (ninguna)"

  if [[ -z $want ]]; then
    if [[ -t 0 && ${#ids[@]} -gt 0 ]]; then
      read -r -p "¿Activar alguna para SSH? Número, id o nombre (Enter = ninguna): " want
    else
      echo "  sin --key y sin terminal interactiva: se crea SIN acceso SSH"
    fi
  fi
  [[ -n $want ]] || { echo "· SSH: desactivado (22/tcp cerrado)"; return 0; }

  for i in "${!ids[@]}"; do
    if [[ $want == "${ids[i]}" || $want == "${names[i]}" || $want == "$((i+1))" ]]; then
      pub=${pubs[i]}
      [[ $pub =~ ^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp[0-9]+)\ [A-Za-z0-9+/=]+(\ [^[:cntrl:]]*)?$ ]] \
        || die "la llave ${names[i]} tiene un formato de clave pública inesperado"
      SSH_KEY_ID=${ids[i]}; SSH_PUBKEY=$pub
      echo "· SSH: activada la llave '${names[i]}' (solo llaves, 22/tcp desde $SSH_FROM)"
      return 0
    fi
  done
  die "no existe la llave '$want'"
}

cmd_keys() { api GET '/keypairs?pageSize=200' | jq -r '.. | objects | select(has("fingerprint") or has("name")) | select(has("id")) | "\(.id)\t\(.name)"'; }

cmd_up() {
  local key_arg=${SSH_KEY:-}
  while (($#)); do
    case $1 in
      --key) key_arg=${2:?--key necesita un valor}; shift 2 ;;
      --key=*) key_arg=${1#--key=}; shift ;;
      *) die "opción desconocida: $1" ;;
    esac
  done
  [[ -z $(state_get serverId) ]] || die "ya hay un servidor en $STATE; usa 'status' o 'down'"
  local fw rules srv act name pass ip
  name="cloudingfy-$(date +%Y%m%d-%H%M%S)"
  select_ssh_key "$key_arg"
  PROXY_HASH=$(printf '%s' "$PROXY_PASS" | openssl passwd -apr1 -stdin)
  gen_tls

  echo "· creando firewall"
  fw=$(api POST /firewalls "$(jq -nc --arg n "$name" '{name:$n, description:"squid https 3142/tcp"}')" | jq -r .id)
  state_set firewallId "$fw"
  state_set tlsPin "$TLS_PIN"
  api POST "/firewalls/$fw/rules" "$(jq -nc --argjson p "$PORT" \
    '{sourceIp:"0.0.0.0/0", protocol:"tcp", description:"squid", portRangeMin:$p, portRangeMax:$p}')" >/dev/null
  if [[ -n $SSH_KEY_ID ]]; then
    api POST "/firewalls/$fw/rules" "$(jq -nc --arg s "$SSH_FROM" \
      '{sourceIp:$s, protocol:"tcp", description:"ssh", portRangeMin:22, portRangeMax:22}')" >/dev/null
  fi

  pass=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
  echo "· creando servidor $name ($FLAVOR, ${DISK_GB}GB)"
  trap 'echo "· fallo: eliminando firewall $fw" >&2; api DELETE "/firewalls/$fw" >/dev/null 2>&1 || true; rm -f "$STATE"' ERR
  srv=$(api POST /servers "$(jq -nc --arg n "$name" --arg f "$FLAVOR" --arg img "$IMAGE_ID" \
    --argjson gb "$DISK_GB" --arg pw "$pass" --arg fw "$fw" --arg ud "$(user_data)" --arg key "$SSH_KEY_ID" '{
      name:$n, hostname:$n, flavorId:$f,
      accessConfiguration:({password:$pw, savePassword:true} + (if $key != "" then {sshKeyId:$key} else {} end)),
      volume:{source:"image", id:$img, ssdGb:$gb},
      userData:$ud,
      publicPortFirewallIds:[$fw]}')")
  trap - ERR
  state_set serverId "$(jq -r .id <<<"$srv")"
  act=$(jq -r '.action.id' <<<"$srv")

  echo "· esperando a que Clouding termine el aprovisionamiento"
  wait_action "$act"
  ip=$(api GET "/servers/$(state_get serverId)" | jq -r '.publicIp')
  state_set publicIp "$ip"

  echo "· esperando a que cloud-init instale squid ($ip:$PORT)"
  local i
  for i in $(seq 1 40); do
    if proxy_check "$ip"; then
      if [[ -n $SSH_KEY_ID ]]; then
        timeout 5 bash -c "echo > /dev/tcp/$ip/22" 2>/dev/null && echo "OK  ssh: root@$ip (solo llaves)" || echo "AVISO: 22/tcp no responde"
      fi
      echo "OK  proxy HTTPS listo en $ip:$PORT (certificado en .proxy-cert.pem)"
      echo "    ./cloudingfy.sh curl https://ifconfig.me"
      return 0
    fi
    sleep 10
  done
  die "el proxy no respondió a tiempo; revisa con './cloudingfy.sh status' (la contraseña root está guardada en Clouding)"
}

cmd_curl() {
  local ip pin; ip=$(state_get publicIp); pin=$(state_get tlsPin)
  [[ -n $ip && -n $pin ]] || die "no hay proxy levantado ($STATE)"
  (($#)) || die "uso: $0 curl URL [opciones de curl]"
  proxy_curl "$ip" "$pin" --proxy-user "$PROXY_USER:$PROXY_PASS" "$@"
}

cmd_generate() {
  local mode=on ip enc_u enc_p url
  case ${1:-} in
    --remove) mode=off ;;
    '') ;;
    *) die "opción desconocida: $1" ;;
  esac
  printf '#!/bin/bash\n# generado por cloudingfy.sh generate (%s)\nset -euo pipefail\n' "$mode"
  printf 'HOST=%q\nPORT=%q\n' "$PROXY_HOST" "$PORT"
  if [[ $mode == on ]]; then
    ip=$(state_get publicIp)
    [[ -n $ip && -f .proxy-cert.pem ]] || die "no hay proxy levantado ($STATE / .proxy-cert.pem)"
    enc_u=$(jq -rn --arg s "$PROXY_USER" '$s|@uri'); enc_p=$(jq -rn --arg s "$PROXY_PASS" '$s|@uri')
    url="https://$enc_u:$enc_p@$PROXY_HOST:$PORT"
    printf 'IP=%q\nURL=%q\nCERT=%q\nMODE=on\n' "$ip" "$url" "$(<.proxy-cert.pem)"
  else
    printf 'MODE=off\n'
  fi
  cat <<'BODY'
[[ $EUID -eq 0 ]] || { echo "ejecútalo como root (| sudo bash)" >&2; exit 1; }
user=${SUDO_USER:-root}
home=$(getent passwd "$user" | cut -d: -f6)
rc=$home/.bashrc
CA=/usr/local/share/ca-certificates/cloudingfy-proxy.crt
APT=/etc/apt/apt.conf.d/01cloudingfy-proxy
DROP=/etc/systemd/system/docker.service.d/10-cloudingfy-proxy.conf

strip_rc() { [[ -f $rc ]] && sed -i '/^# >>> cloudingfy >>>$/,/^# <<< cloudingfy <<<$/d' "$rc" || true; }
# se reescribe en sitio (sin rename): /etc/hosts puede ser un bind-mount (contenedores)
strip_hosts() { local t; t=$(grep -v ' # cloudingfy$' /etc/hosts || true); printf '%s\n' "$t" > /etc/hosts; }

if [[ $MODE == off ]]; then
  rm -f "$APT" "$CA" "$DROP"; strip_hosts; strip_rc
  if [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    command -v dockerd >/dev/null && echo "docker: reinicia el daemon para dejar de usar el proxy (systemctl restart docker)"
  fi
  command -v update-ca-certificates >/dev/null && update-ca-certificates --fresh >/dev/null || true
  echo "cloudingfy: configuración de proxy eliminada (abre una shell nueva para limpiar las variables)"
  exit 0
fi

# 1) certificado del proxy como de confianza (apt, curl, git, python...)
if command -v update-ca-certificates >/dev/null; then
  install -d /usr/local/share/ca-certificates
  printf '%s\n' "$CERT" > "$CA"
  update-ca-certificates >/dev/null
else
  echo "AVISO: no hay update-ca-certificates; instala el certificado a mano" >&2
fi

# 2) nombre del proxy
strip_hosts
echo "$IP $HOST # cloudingfy" >> /etc/hosts

# 3) apt
if [[ -d /etc/apt/apt.conf.d ]]; then
  printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' "$URL" "$URL" > "$APT"
  chmod 600 "$APT"
fi

# 5) daemon de Docker (pulls de imágenes). En systemd '%' es un especificador: se escapa como '%%'.
#    No afecta al tráfico que generan los procesos DENTRO de los contenedores.
if command -v dockerd >/dev/null && [[ -d /run/systemd/system ]]; then
  esc=${URL//\%/%%}
  install -d "$(dirname "$DROP")"
  printf '[Service]\nEnvironment="HTTP_PROXY=%s" "HTTPS_PROXY=%s" "NO_PROXY=localhost,127.0.0.1,::1"\n' "$esc" "$esc" > "$DROP"
  chmod 600 "$DROP"
  systemctl daemon-reload
  if [[ -z $(docker ps -q 2>/dev/null) ]]; then
    systemctl restart docker && echo "docker: daemon reiniciado con el proxy"
  else
    echo "AVISO docker: hay contenedores en marcha; no reinicio. Cuando puedas: systemctl restart docker" >&2
  fi
fi

# 4) shell
strip_rc
{
  echo '# >>> cloudingfy >>>'
  for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; do echo "export $v='$URL'"; done
  echo "export no_proxy='localhost,127.0.0.1,::1'"
  echo '# <<< cloudingfy <<<'
} >> "$rc"
chown "$user": "$rc" 2>/dev/null || true

echo "cloudingfy: proxy https://$HOST:$PORT ($IP) configurado para apt, docker (si existe) y $rc"
echo "            abre una shell nueva o: source $rc"
BODY
}

cmd_status() {
  local id; id=$(state_get serverId)
  [[ -n $id ]] || die "no hay servidor en $STATE"
  api GET "/servers/$id" | jq '{id,name,status,powerState,flavor,publicIp}'
  proxy_check "$(state_get publicIp)" || true
}

cmd_down() {
  local id fw act
  id=$(state_get serverId); fw=$(state_get firewallId)
  [[ -n $id || -n $fw ]] || die "nada que borrar en $STATE"
  if [[ -n $id ]]; then
    echo "· eliminando servidor $id"
    act=$(api DELETE "/servers/$id" | jq -r '.id')
    wait_action "$act"
  fi
  if [[ -n $fw ]]; then
    echo "· eliminando firewall $fw"
    api DELETE "/firewalls/$fw" >/dev/null
  fi
  rm -f "$STATE"
  echo "OK"
}

case ${1:-} in
  cost) cmd_cost ;;
  keys) cmd_keys ;;
  up) shift; cmd_up "$@" ;;
  status) cmd_status ;;
  curl) shift; cmd_curl "$@" ;;
  generate) shift; cmd_generate "$@" ;;
  down) cmd_down ;;
  *) sed -n '2,18p' "$0"; exit 1 ;;
esac
