-- name: FindAccount :one
SELECT a.id           AS id,
       a.name         AS name,
       a.pwd          AS pwd,
       a.access_level AS access_level,
       a.last_server  AS last_server,
       a.banned       AS banned
FROM l2auth.account a
WHERE a.name = lower($1)
LIMIT 1;

-- name: RegisterAccount :one
INSERT INTO l2auth.account (name, pwd, last_ip)
VALUES ($1, $2, $3)
RETURNING id;

-- name: UpdateAccountLastIPByName :exec
UPDATE l2auth.account
SET
    last_ip = $2,
    modify_date = now()
WHERE name = $1;

-- name: UpdateAccountLastServer :exec
UPDATE l2auth.account
SET
    last_server = $2,
    modify_date = now()
WHERE name = $1;

-- name: UpdateAccountPasswordByName :exec
UPDATE l2auth.account
SET
    pwd = $2,
    modify_date = now()
WHERE name = $1;

-- name: AddIPBan :exec
INSERT INTO l2auth.ip_banned (ip, expiry_date, reason)
VALUES ($1, $2, $3)
ON CONFLICT (ip) DO UPDATE
SET expiry_date = EXCLUDED.expiry_date,
    reason = EXCLUDED.reason;

-- name: RemoveIPBan :exec
DELETE FROM l2auth.ip_banned
WHERE ip = $1;

-- name: GetActiveIPBans :many
SELECT ip, expiry_date, reason
FROM l2auth.ip_banned
WHERE expiry_date > now();

-- name: IsIPBanned :one
SELECT EXISTS (
    SELECT 1
    FROM l2auth.ip_banned
    WHERE ip = $1 AND expiry_date > now()
);