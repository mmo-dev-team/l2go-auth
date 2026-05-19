CREATE SCHEMA IF NOT EXISTS l2auth;

CREATE TABLE IF NOT EXISTS l2auth.account
(
    id            BIGSERIAL                   NOT NULL,
    name          VARCHAR                     NOT NULL,
    pwd           VARCHAR                     NOT NULL,
    access_level  INT                         NOT NULL DEFAULT 0,
    last_server   INT                         NOT NULL DEFAULT 0,
    banned        BOOLEAN                     NOT NULL DEFAULT FALSE,
    last_ip       INET,
    modify_date   TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    creation_date TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT account__pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS account__name_lower__uniq ON l2auth.account (lower(name));

CREATE TABLE IF NOT EXISTS l2auth.ip_banned
(
    ip          INET                        NOT NULL,
    expiry_date TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    reason      VARCHAR                     NOT NULL DEFAULT '',
    CONSTRAINT ip_banned__pkey PRIMARY KEY (ip)
);