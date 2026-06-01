# ngx_http_auth_internal_module

`ngx_http_auth_internal_module` validates an internal authentication fingerprint header.

## Synopsis

```nginx
http {
    auth_internal on;
    auth_internal_secrets secret1 secret2;
    auth_internal_timeout 600;
    auth_internal_header X-Fingerprint;
    auth_internal_empty_deny off;
    auth_internal_failure_deny on;
}
```

## Installation

```sh
./configure --add-module=/path/to/ngx_http_auth_internal_module
```

## Directives

### auth_internal

**Syntax:** `auth_internal on | off;`

**Default:** `auth_internal off;`

**Context:** `http`, `server`

Enables or disables internal fingerprint validation.

### auth_internal_secrets

**Syntax:** `auth_internal_secrets secret ...;`

**Default:** `-`

**Context:** `http`, `server`

Configures one or more secrets used to validate the fingerprint header.

### auth_internal_empty_deny

**Syntax:** `auth_internal_empty_deny on | off;`

**Default:** `auth_internal_empty_deny off;`

**Context:** `http`, `server`

When enabled, requests without the fingerprint header are rejected.

### auth_internal_failure_deny

**Syntax:** `auth_internal_failure_deny on | off;`

**Default:** `auth_internal_failure_deny on;`

**Context:** `http`, `server`

When enabled, invalid or expired fingerprints are rejected.

### auth_internal_timeout

**Syntax:** `auth_internal_timeout time;`

**Default:** `auth_internal_timeout 300s;`

**Context:** `http`, `server`

Sets the maximum allowed fingerprint age.

### auth_internal_header

**Syntax:** `auth_internal_header header;`

**Default:** `auth_internal_header X-Fingerprint;`

**Context:** `http`, `server`

Sets the request header used for fingerprint validation.

## Variables

### $auth_internal_result

Contains the validation result, such as `off`, `empty`, `failure`, or `success`.

## License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
