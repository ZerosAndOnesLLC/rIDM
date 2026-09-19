#!/bin/sh
# Writes ./secrets for compose.yml: random passwords for the three database
# roles and Valkey, the connection URLs built from them, the master key, a
# metrics token and, if BOOTSTRAP_ADMIN_EMAIL is set in .env, the first
# administrator's one-time password. Files that already exist are kept, so it
# is safe to run again; it never rotates anything.
#
# The directory is 0700. The files are 0644 inside it, because compose mounts
# them unchanged and the containers read them as their own non-root users.
#
# Keep a copy of secrets/master_key somewhere other than this host: without it
# a restored database cannot decrypt its signing keys or MFA secrets.
#
# RIDM_SECRETS_DIR and RIDM_CERTS_DIR move the two directories, as they do for
# compose.yml; BOOTSTRAP_ADMIN_EMAIL in the environment wins over .env.
set -eu

cd "$(dirname "$0")"
umask 022
secrets=${RIDM_SECRETS_DIR:-./secrets}
mkdir -p "$secrets" "${RIDM_CERTS_DIR:-./certs}"
chmod 700 "$secrets"

random() { openssl rand -hex "$1"; }

# write NAME VALUE: create secrets/NAME unless it exists with content.
write() {
    if [ -s "$secrets/$1" ]; then
        return
    fi
    printf '%s\n' "$2" > "$secrets/$1.tmp"
    chmod 644 "$secrets/$1.tmp"
    mv "$secrets/$1.tmp" "$secrets/$1"
    echo "wrote $secrets/$1"
}

# read NAME: the first line of secrets/NAME.
read_secret() { head -n 1 "$secrets/$1"; }

bootstrap_email=${BOOTSTRAP_ADMIN_EMAIL:-}
if [ -z "$bootstrap_email" ] && [ -f .env ]; then
    bootstrap_email=$(sed -n 's/^BOOTSTRAP_ADMIN_EMAIL=//p' .env | tail -n 1)
fi

write postgres_password "$(random 24)"
write migrator_password "$(random 24)"
write app_password "$(random 24)"
write valkey_password "$(random 24)"
write master_key "$(random 32)"
write metrics_token "$(random 24)"

write database_url "postgres://ridm_app:$(read_secret app_password)@postgres:5432/ridm"
write migrator_database_url "postgres://ridm_migrator:$(read_secret migrator_password)@postgres:5432/ridm"
write redis_url "redis://:$(read_secret valkey_password)@valkey:6379"

# Mounted whether or not they are used; an empty file is an unset setting.
if [ ! -e "$secrets/smtp_password" ]; then
    : > "$secrets/smtp_password"
    chmod 644 "$secrets/smtp_password"
    echo "wrote $secrets/smtp_password (empty; put the SMTP password here if SMTP_HOST is set)"
fi
if [ -n "$bootstrap_email" ]; then
    write bootstrap_admin_password "Ridm-$(random 12)"
    echo "first administrator: $bootstrap_email, password in $secrets/bootstrap_admin_password"
elif [ ! -e "$secrets/bootstrap_admin_password" ]; then
    : > "$secrets/bootstrap_admin_password"
    chmod 644 "$secrets/bootstrap_admin_password"
fi
