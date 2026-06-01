
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_str_t      result;
} ngx_http_auth_internal_ctx_t;


typedef struct {
    ngx_flag_t     enable;
    ngx_array_t   *secrets;
    ngx_flag_t     empty_deny;
    ngx_flag_t     failure_deny;
    time_t         timeout;
    ngx_str_t      header_name;
} ngx_http_auth_internal_srv_conf_t;


static ngx_int_t ngx_http_auth_internal_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_internal_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_str_t ngx_http_auth_internal_compute_md5_hex(
    ngx_http_request_t *r, const u_char *data, size_t len);
static ngx_table_elt_t *ngx_http_auth_internal_get_header(
    ngx_http_request_t *r, ngx_str_t *name);
static ngx_int_t ngx_http_auth_internal_deny(ngx_http_request_t *r,
    const char *log_message, ngx_uint_t deny_flag);
static ngx_int_t ngx_http_auth_internal_handler(ngx_http_request_t *r);
static void *ngx_http_auth_internal_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_auth_internal_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_internal_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_auth_internal_commands[] = {

    { ngx_string("auth_internal"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auth_internal_srv_conf_t, enable),
      NULL },

    { ngx_string("auth_internal_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auth_internal_srv_conf_t, secrets),
      NULL },

    { ngx_string("auth_internal_empty_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auth_internal_srv_conf_t, empty_deny),
      NULL },

    { ngx_string("auth_internal_failure_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auth_internal_srv_conf_t, failure_deny),
      NULL },

    { ngx_string("auth_internal_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auth_internal_srv_conf_t, timeout),
      NULL },

    { ngx_string("auth_internal_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auth_internal_srv_conf_t, header_name),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_internal_module_ctx = {
    ngx_http_auth_internal_add_variables,    /* preconfiguration */
    ngx_http_auth_internal_init,             /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    ngx_http_auth_internal_create_srv_conf,  /* create server configuration */
    ngx_http_auth_internal_merge_srv_conf,   /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_internal_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_internal_module_ctx,      /* module context */
    ngx_http_auth_internal_commands,         /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_auth_internal_result_off = ngx_string("off");
static ngx_str_t  ngx_http_auth_internal_result_empty = ngx_string("empty");
static ngx_str_t  ngx_http_auth_internal_result_failure = ngx_string("failure");
static ngx_str_t  ngx_http_auth_internal_result_success = ngx_string("success");
static ngx_str_t  ngx_http_auth_internal_result_secrets_not_configured =
    ngx_string("secrets_not_configured");


static ngx_http_variable_t  ngx_http_auth_internal_vars[] = {

    { ngx_string("auth_internal_result"), NULL,
      ngx_http_auth_internal_result_variable,
      0, 0, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_auth_internal_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_auth_internal_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_internal_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_internal_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_internal_module);

    if (ctx == NULL || ctx->result.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->result.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->result.data;

    return NGX_OK;
}


static ngx_str_t
ngx_http_auth_internal_compute_md5_hex(ngx_http_request_t *r,
    const u_char *data, size_t len)
{
    ngx_md5_t  md5;
    u_char     digest[16];
    ngx_str_t  md5_hex;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, len);
    ngx_md5_final(digest, &md5);

    md5_hex.len = 32;
    md5_hex.data = ngx_pnalloc(r->pool, md5_hex.len);
    if (md5_hex.data == NULL) {
        md5_hex.len = 0;
        return md5_hex;
    }

    ngx_hex_dump(md5_hex.data, digest, 16);

    return md5_hex;
}


static ngx_table_elt_t *
ngx_http_auth_internal_get_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == name->len
            && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            return &h[i];
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_auth_internal_deny(ngx_http_request_t *r, const char *log_message,
    ngx_uint_t deny_flag)
{
    if (deny_flag) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", log_message);
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_auth_internal_handler(ngx_http_request_t *r)
{
    time_t                             timestamp, current_time;
    ngx_uint_t                         i;
    ngx_str_t                          fingerprint, md5sum, computed_md5;
    ngx_str_t                          data;
    ngx_str_t                         *secret;
    ngx_table_elt_t                   *h;
    ngx_http_auth_internal_ctx_t      *ctx;
    ngx_http_auth_internal_srv_conf_t *conf;
    u_char                             timestamp_hex[9];
    u_char                             md5sum_data[33];

    conf = ngx_http_get_module_srv_conf(r, ngx_http_auth_internal_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_internal_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_internal_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_auth_internal_module);
    }

    if (!conf->enable) {
        ctx->result = ngx_http_auth_internal_result_off;
        return NGX_DECLINED;
    }

    h = ngx_http_auth_internal_get_header(r, &conf->header_name);
    if (h == NULL) {
        ctx->result = ngx_http_auth_internal_result_empty;
        return ngx_http_auth_internal_deny(r,
            "auth internal: denied access due to empty fingerprint",
            conf->empty_deny);
    }

    fingerprint = h->value;
    if (fingerprint.len < 40) {
        ctx->result = ngx_http_auth_internal_result_failure;
        return ngx_http_auth_internal_deny(r,
            "auth internal: denied access due to invalid fingerprint format",
            conf->failure_deny);
    }

    ngx_memcpy(timestamp_hex, fingerprint.data, 8);
    timestamp_hex[8] = '\0';
    ngx_memcpy(md5sum_data, fingerprint.data + 8, 32);
    md5sum_data[32] = '\0';

    md5sum.len = 32;
    md5sum.data = md5sum_data;

    timestamp = (time_t) ngx_hextoi(timestamp_hex, 8);
    if (timestamp == (time_t) NGX_ERROR || timestamp == 0) {
        ctx->result = ngx_http_auth_internal_result_failure;
        return ngx_http_auth_internal_deny(r,
            "auth internal: denied access due to invalid fingerprint timestamp",
            conf->failure_deny);
    }

    current_time = ngx_time();
    if ((current_time - timestamp) > conf->timeout) {
        ctx->result = ngx_http_auth_internal_result_failure;
        return ngx_http_auth_internal_deny(r,
            "auth internal: denied access due to fingerprint timeout",
            conf->failure_deny);
    }

    if (conf->secrets == NULL || conf->secrets->nelts == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "auth internal: skipped due to secrets not configured");
        ctx->result = ngx_http_auth_internal_result_secrets_not_configured;
        return NGX_DECLINED;
    }

    secret = conf->secrets->elts;

    for (i = 0; i < conf->secrets->nelts; i++) {
        data.len = secret[i].len + 8;
        data.data = ngx_pnalloc(r->pool, data.len);
        if (data.data == NULL) {
            ctx->result = ngx_http_auth_internal_result_failure;
            return ngx_http_auth_internal_deny(r,
                "auth internal: failed to allocate memory",
                conf->failure_deny);
        }

        ngx_memcpy(data.data, secret[i].data, secret[i].len);
        ngx_memcpy(data.data + secret[i].len, timestamp_hex, 8);

        computed_md5 = ngx_http_auth_internal_compute_md5_hex(r, data.data,
                                                              data.len);
        if (computed_md5.len == 0) {
            ctx->result = ngx_http_auth_internal_result_failure;
            return ngx_http_auth_internal_deny(r,
                "auth internal: denied access due to empty fingerprint hash",
                conf->failure_deny);
        }

        if (computed_md5.len == md5sum.len
            && ngx_strncmp(computed_md5.data, md5sum.data, md5sum.len) == 0)
        {
            ctx->result = ngx_http_auth_internal_result_success;
            return NGX_DECLINED;
        }
    }

    ctx->result = ngx_http_auth_internal_result_failure;
    return ngx_http_auth_internal_deny(r,
        "auth internal: denied access due to fingerprint hash mismatch",
        conf->failure_deny);
}


static void *
ngx_http_auth_internal_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_auth_internal_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_internal_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->secrets = NGX_CONF_UNSET_PTR;
    conf->empty_deny = NGX_CONF_UNSET;
    conf->failure_deny = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_auth_internal_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_auth_internal_srv_conf_t  *prev = parent;
    ngx_http_auth_internal_srv_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->secrets, prev->secrets, NULL);
    ngx_conf_merge_value(conf->empty_deny, prev->empty_deny, 0);
    ngx_conf_merge_value(conf->failure_deny, prev->failure_deny, 1);
    ngx_conf_merge_value(conf->timeout, prev->timeout, 300);
    ngx_conf_merge_str_value(conf->header_name, prev->header_name,
                             "X-Fingerprint");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_internal_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_internal_handler;

    return NGX_OK;
}
