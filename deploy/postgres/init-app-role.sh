#!/bin/sh
# Runs once on first database initialisation (docker-entrypoint-initdb.d).
#
# Creates the NON-superuser role the API connects as. Postgres superusers bypass
# row level security, so the application must never connect as one: tenant
# isolation is enforced by RLS policies that only apply to ordinary roles.
set -eu

: "${RIDM_APP_USER:=ridm_app}"
: "${RIDM_APP_PASSWORD:=ridm_app}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE "${RIDM_APP_USER}" LOGIN PASSWORD '${RIDM_APP_PASSWORD}'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT, CREATE, TEMP ON DATABASE "${POSTGRES_DB}" TO "${RIDM_APP_USER}";
GRANT ALL ON SCHEMA public TO "${RIDM_APP_USER}";
SQL
