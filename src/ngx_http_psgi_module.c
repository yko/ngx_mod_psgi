#include "ngx_http_psgi_module.h"
#include "ngx_http_psgi_perl.h"

ngx_command_t  ngx_http_psgi_commands[] = {
    /* psgi should be set to absolute (?) path to .psgi application launcher */
    { ngx_string("psgi"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
        ngx_http_psgi,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_psgi_loc_conf_t, perl),
        NULL },
    ngx_null_command
};

ngx_http_module_t     ngx_http_psgi_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_psgi_create_main_conf,        /* create main configuration */
    ngx_http_psgi_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_psgi_create_loc_conf,         /* create location configuration */
    ngx_http_psgi_merge_loc_conf           /* merge location configuration */
};

ngx_module_t          ngx_http_psgi_module = {
    NGX_MODULE_V1,
    &ngx_http_psgi_module_ctx,              // module context
    ngx_http_psgi_commands,                 // module directives
    NGX_HTTP_MODULE,                        // module type
    NULL,                                   // init master
    NULL,                                   // init module
    ngx_http_psgi_init_worker,              // init process
    NULL,                                   // init thread
    NULL,                                   // exit thread
    ngx_http_psgi_exit,                     // exit process
    NULL,                                   // exit master
    NGX_MODULE_V1_PADDING
};

char *
ngx_http_psgi(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_psgi_loc_conf_t *psgilcf = conf;

    ngx_str_t                  *value;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_psgi_main_conf_t  *psgimcf;

    value = cf->args->elts;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0, 
            "Installing psgi handler \"%V\"", &value[1]);

    if (psgilcf->app != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "duplicate psgi app \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    psgimcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_psgi_module);

    if (psgimcf->perl == NULL) {
        if (ngx_http_psgi_init_interpreter(cf, psgimcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    psgilcf->app = ngx_palloc(cf->pool, value[1].len + 1);
    ngx_cpymem(psgilcf->app, value[1].data, value[1].len + 1);

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_psgi_handler;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_psgi_init_worker(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "perl term");

    /* TODO: Should I do here something nginx-related?
     * Or just bind init_worker right to Perl land? 
     */

    return ngx_http_psgi_perl_init_worker(cycle);
}

ngx_int_t
ngx_http_psgi_handler(ngx_http_request_t *r)
{
    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;
    r->request_body_file_log_level = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Loading body for PSGI request");

    ngx_http_read_client_request_body(r, ngx_http_psgi_handler_with_body);
    /* TODO: Handle errors */

    return NGX_OK;
}

void ngx_http_psgi_handler_with_body(ngx_http_request_t *r)
{
    ngx_http_psgi_main_conf_t  *psgimcf;
    ngx_http_psgi_loc_conf_t   *psgilcf;
    ngx_log_t *log = r->connection->log;

    psgilcf = ngx_http_get_module_loc_conf(r, ngx_http_psgi_module);
    psgimcf = ngx_http_get_module_main_conf(r, ngx_http_psgi_module);


    if (psgilcf->app == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                "PSGI panic: NULL application");
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Serving request with PSGI app \"%s\"",
                    psgilcf->app);

    /* No local interpreter. Reuse main */
    if (psgilcf->perl == NULL) {
        if (psgilcf->perl == NULL) {
            return;
        }
    }

    ngx_http_psgi_perl_handler(r, psgilcf, psgimcf->perl);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
            "Finished serving request");
}

void *
ngx_http_psgi_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_psgi_main_conf_t  *pmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, 
            "Create PSGI main conf");

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_psgi_main_conf_t));

    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->perl = NULL;

    return pmcf;
}

char *
ngx_http_psgi_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, 
            "Init psgi main conf");

    return NGX_CONF_OK;
}

void *
ngx_http_psgi_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_psgi_loc_conf_t *psgilcf;

    psgilcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_psgi_loc_conf_t));

    if (psgilcf == NULL) {
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, 
            "create PSGI local conf");

    psgilcf->sub = NULL;

    return psgilcf;
}

char *
ngx_http_psgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_psgi_loc_conf_t *conf = child;
    ngx_http_psgi_loc_conf_t *prev = parent;

    /* FIXME: Do I need this at all? */
    if (conf->app == NULL) {
        conf->sub = prev->sub;
        conf->app = prev->app;
    }

    /* TODO: optional localization of Perl interpreter per app? */
    if (conf->app != NULL && conf->perl == NULL) {
        conf->perl = prev->perl;
        if (conf->perl == NULL) {
            conf->perl = ngx_http_psgi_create_interpreter(cf);
        }
    }

    return NGX_CONF_OK;
}

char *
ngx_http_psgi_init_interpreter(ngx_conf_t *cf, ngx_http_psgi_main_conf_t *psgimcf)
{
    /* Already have Perl interpreter */
    if (psgimcf->perl != NULL) {
        return NGX_CONF_OK;
    }

    psgimcf->perl = ngx_http_psgi_create_interpreter(cf);

    if (psgimcf->perl == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, 
            "Perl interpreter created");

    return NGX_CONF_OK;
}

void
ngx_http_psgi_exit(ngx_cycle_t *cycle)
{
    ngx_http_psgi_perl_exit(cycle);
}
