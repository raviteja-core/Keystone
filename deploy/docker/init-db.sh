#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER keystone_auth_app WITH PASSWORD 'auth_dev_password';
    CREATE DATABASE keystone_auth OWNER keystone_auth_app;
    GRANT ALL PRIVILEGES ON DATABASE keystone_auth TO keystone_auth_app;

    CREATE USER keystone_authz_app WITH PASSWORD 'authz_dev_password';
    CREATE DATABASE keystone_authz OWNER keystone_authz_app;
    GRANT ALL PRIVILEGES ON DATABASE keystone_authz TO keystone_authz_app;
EOSQL
