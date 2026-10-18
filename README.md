# ngx_http_auth_internal_module

`ngx_http_auth_internal_module` validates an internal authentication fingerprint header.

## Synopsis

```nginx
http {
    auth_internal on;
    auth_internal_secret secret1;
    auth_internal_secret secret2;
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

To enable `expr` and `when`, build `ngx_expr_module` statically in
the same Nginx configuration:

```sh
./configure \
    --add-module=/path/to/ngx_expr_module \
    --add-module=/path/to/ngx_http_auth_internal_module
```

## Conditional configuration

All module directives support `http` and `server`. When
[`ngx_expr_module`](https://git.hanada.info/hanada/ngx_condition_module)
is built into Nginx, they also support `when` in those contexts:

```nginx
expr internal_auth_enabled str_eq $host internal.example.com;

when internal_auth_enabled {
    auth_internal on;
    auth_internal_secret internal_secret;
    auth_internal_timeout 60s;
}

auth_internal off;
```

Each single-value directive selects the first matching value independently,
including unconditional values, so put its unconditional fallback after
conditional values.

`auth_internal_secret` instead checks all enabled secrets at the current level
in declaration order. Unconditional secrets always participate. Secrets from
the previous level are used only if no secret at the current level is enabled;
a failed fingerprint check does not retry the previous level's secrets.
Splitting declarations into separate blocks with the same condition does not
change this behavior.

## Directives

### auth_internal

**syntax:** `auth_internal on | off`

**default:** `auth_internal off`

**context:** `http`, `server`, `when`

Enables or disables internal fingerprint validation.

### auth_internal_secret

**syntax:** `auth_internal_secret secret`

**default:** none

**context:** `http`, `server`, `when`

Configures a secret used to validate the fingerprint header. This directive
can be specified multiple times to support secret rotation.

### auth_internal_empty_deny

**syntax:** `auth_internal_empty_deny on | off`

**default:** `auth_internal_empty_deny off`

**context:** `http`, `server`, `when`

When enabled, requests without the fingerprint header are rejected.

### auth_internal_failure_deny

**syntax:** `auth_internal_failure_deny on | off`

**default:** `auth_internal_failure_deny on`

**context:** `http`, `server`, `when`

When enabled, invalid or expired fingerprints are rejected.

### auth_internal_timeout

**syntax:** `auth_internal_timeout time`

**default:** `auth_internal_timeout 300s`

**context:** `http`, `server`, `when`

Sets the maximum allowed fingerprint age.

### auth_internal_header

**syntax:** `auth_internal_header header`

**default:** `auth_internal_header X-Fingerprint`

**context:** `http`, `server`, `when`

Sets the request header used for fingerprint validation.

## Variables

### $auth_internal_result

Contains the validation result, such as `off`, `empty`, `failure`, or `success`.

## License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
