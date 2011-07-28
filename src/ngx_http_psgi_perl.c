#include "ngx_http_psgi_perl.h"
#include "ngx_http_psgi_response.h"
#include "ngx_http_psgi_error_stream.h"
#include "ngx_http_psgi_input_stream.h"
EXTERN_C void xs_init (pTHX);

SV *ngx_http_psgi_create_env(pTHX_ ngx_http_request_t *r, char *app)
{
    ngx_list_part_t        *part;
    ngx_table_elt_t        *h;
    ngx_uint_t              i, c, x;


    SV  *_version[2];
    AV  *version;

    HV* env = newHV();

    /* PSGI version 1.0, arrayref [1,0] */
    _version[0] = newSViv(1);
    _version[1] = newSViv(0);
    version = av_make(2, _version);
    hv_store(env, "psgi.version", sizeof("psgi.version")-1, newRV_inc((SV*)version), 0);

    /* FIXME: after any of this two operations $! is set to 'Inappropriate ioctl for device' */
    SV *errors_h = PerlIONginxError_newhandle(aTHX_ r);
    if (errors_h == NULL)
        return NULL;
    hv_store(env, "psgi.errors", sizeof("psgi.errors")-1, errors_h, 0);

    SV *input_h = PerlIONginxInput_newhandle(aTHX_ r);
    if (input_h == NULL)
        return NULL;
    hv_store(env, "psgi.input", sizeof("psgi.input")-1, input_h, 0);

    /* Detect scheme.
     * TODO: Check if only http and https schemes allowed here. What about ws and others?
     * FIXME: mb nginx should parse scheme in safe way: [a-z][a-z0-9\=\0\.]* allowed to be valid scheme (rfc3986)
     * but nginx allows only [a-z]+
     */
#if (NGX_HTTP_SSL)
    char *scheme;
    if (r->connection->ssl) {
        scheme = "https";
    } else {
        scheme = "http";
    }
    hv_store(env, "psgi.url_scheme", sizeof("psgi.url_scheme")-1, newSVpv(scheme, 0), 0);
#else
    hv_store(env, "psgi.url_scheme", sizeof("psgi.url_scheme")-1, newSVpv("http", 0), 0);
#endif

    // Buffered body in file
    if (r->request_body != NULL && r->request_body->temp_file != NULL) {
        hv_store(env, "psgix.input.buffered", sizeof("psgix.input.buffered")-1, newSViv(1), 0);
    }

    /* port defined in first line of HTTP request and parsed by nginx */
    if (r->port_start) {
        STRLEN port_len = r->port_end - r->port_start;
        hv_store(env, "SERVER_PORT", sizeof("SERVER_PORT")-1, newSVpv((char *)r->port_start, port_len), 0);
    } else {
        /* copypasted from ngx_http_variables.c: get port from nginx conf  */
        /* TODO: Maybe reuse code from ngx_http_variables.c is a good idea? */
        ngx_uint_t            port;
        struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6  *sin6;
#endif
        u_char *strport;

        if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
            // TODO: Throw error
            return NULL;
        }

        strport = ngx_pnalloc(r->pool, sizeof("65535") - 1);
        if (strport == NULL) {
            return NULL;
        }

        switch (r->connection->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) r->connection->local_sockaddr;
                port = ntohs(sin6->sin6_port);
                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) r->connection->local_sockaddr;
                port = ntohs(sin->sin_port);
                break;
        }

        if (port > 0 && port < 65536) {
            hv_store(env, "SERVER_PORT", sizeof("SERVER_PORT")-1, newSVuv(port), 0);
        } else {
            hv_store(env, "SERVER_PORT", sizeof("SERVER_PORT")-1, newSVpv("", 0), 0);
        }
    }
    hv_store(env, "SERVER_PROTOCOL", sizeof("SERVER_PROTOCOL")-1, newSVpv((char *)r->http_protocol.data, r->http_protocol.len), 0);

    if (r->headers_in.content_length_n != -1) {
        hv_store(env, "CONTENT_LENGTH", sizeof("CONTENT_LENGTH")-1, newSViv(r->headers_in.content_length_n), 0);
    }

    if (r->headers_in.content_type != NULL) {
        hv_store(env, "CONTENT_TYPE", sizeof("CONTENT_TYPE")-1, 
                newSVpv((char*)r->headers_in.content_type->value.data, r->headers_in.content_type->value.len), 0);
    }

    hv_store(env, "REQUEST_URI", sizeof("REQUEST_URI")-1, newSVpv((char *)r->unparsed_uri.data, r->unparsed_uri.len), 0);

    /* TODO: SCRIPT_NAME should be string matched by 'location' value in nginx.conf */
    hv_store(env, "SCRIPT_NAME", sizeof("SCRIPT_NAME")-1, newSVpv("", 0), 0);

    /* FIXME:
     * PATH_INFO should be relative to SCRIPT_NAME (current 'location') path in nginx.conf
     * How to achieve this? Should I allow psgi only in 'exact match' locations?
     * It would be hard to find PATH_INFO for locations like "location ~ /(foo|bar)/.* { }". Or it wouldn't?
     */
    hv_store(env, "PATH_INFO", sizeof("PATH_INFO")-1, newSVpv((char *)r->uri.data, r->uri.len), 0);
    hv_store(env, "REQUEST_METHOD", sizeof("REQUEST_METHOD")-1, newSVpv((char *)r->method_name.data, r->method_name.len), 0);
    if (r->args.len > 0) {
        hv_store(env, "QUERY_STRING", sizeof("QUERY_STRING")-1, newSVpv((char *)r->args.data, r->args.len), 0);
    } else {
        hv_store(env, "QUERY_STRING", sizeof("QUERY_STRING")-1, newSVpv("", 0), 0);
    }

    if (r->host_start && r->host_end) {
        hv_store(env, "SERVER_NAME", sizeof("SERVER_NAME")-1, newSVpv((char *)r->host_start, r->host_end - r->host_start), 0);
    } else {
        ngx_http_core_srv_conf_t  *cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
        hv_store(env, "SERVER_NAME", sizeof("SERVER_NAME")-1, newSVpv((char *)cscf->server_name.data, cscf->server_name.len), 0);
    }

    hv_store(env, "REMOTE_ADDR", sizeof("REMOTE_ADDR")-1, newSVpv((char *)r->connection->addr_text.data, r->connection->addr_text.len), 0);
    /* TODO
     *
     * psgi.multithread
     * psgi.multiprocess
     */

    part = &r->headers_in.headers.part;
    h = part->elts;

    c = 0;
    for (i = 0; /* void */ ; i++) {
        ngx_str_t  name;
        u_char *p;
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }
        p = ngx_pnalloc(r->pool, sizeof("HTTP_") - 1 + h[i].key.len);

        if (p == NULL) {
            return NULL;
        }

        name.data = p;
        name.len = sizeof("HTTP_") + h[i].key.len -1 ;

        p = ngx_copy(p, (u_char*)"HTTP_", sizeof("HTTP_")-1);
        p = ngx_copy(p, h[i].key.data, h[i].key.len );

        ngx_log_debug7(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "Set env header: '%s' => '%s'",
                h[i].key.data, h[i].value.data);

        x = h[i].key.len + sizeof("HTTP_");
        while (x > 0) {
            if (name.data[x] == '-') {
                name.data[x] = '_';
            } else {
                name.data[x] = ngx_toupper(name.data[x]);
            }
            x--;
        }
        SV **exists = hv_fetch(env, (char*)name.data, name.len, 0);
        if (exists == NULL) {
            hv_store(env, (char *)name.data, name.len, newSVpv((char *)h[i].value.data, h[i].value.len), 0);
        } else {
            /* join ',', @values;
             * FIXME: Can I do this better
             */
            SV *newval = newSVpvf("%s,%s", SvPV_nolen(*exists), h[i].value.data);
            hv_store(env, (char *)name.data, name.len, newval, 0);
        }
        c += 2;
    }

    return newRV_inc((SV*)env);
}

ngx_int_t
ngx_http_psgi_perl_handler(ngx_http_request_t *r, ngx_http_psgi_loc_conf_t *psgilcf, void *interpreter)
{
    PerlInterpreter *perl = (PerlInterpreter *) interpreter;
    ngx_int_t retval = NGX_ERROR;
    ngx_log_t *log = r->connection->log;

    dTHXa(perl);
    PERL_SET_CONTEXT(perl);

    if (psgilcf->sub == NULL) {

        if(ngx_http_psgi_init_app(aTHX_ psgilcf, log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    {
        int count;

        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, 0,
                "Running PSGI app \"%s\"",
                psgilcf->app);

        SV *env = ngx_http_psgi_create_env(aTHX_ r, psgilcf->app);

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);

        XPUSHs(sv_2mortal(env));

        PUTBACK;

        count = call_sv(psgilcf->sub, G_EVAL|G_SCALAR);

        ngx_log_debug7(NGX_LOG_DEBUG_HTTP, log, 0,
                "PSGI app response: %d elements", count);

        SPAGAIN;

        if (SvTRUE(ERRSV))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "PSGI handler execution failed: %s", SvPV_nolen(ERRSV));

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            retval = NGX_ERROR;
        }
        else if (count < 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "PSGI app \"%s\" did not returned value: %s", psgilcf->app, SvPV_nolen(ERRSV));
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            retval = NGX_ERROR;
        } else {
            retval = ngx_http_psgi_process_response(aTHX_ r, POPs, perl);
            ngx_http_finalize_request(r, retval);
        }

        PUTBACK;
        FREETMPS;
        LEAVE;
    }
    return retval;
}

ngx_int_t
ngx_http_psgi_init_app(pTHX_ ngx_http_psgi_loc_conf_t *psgilcf, ngx_log_t *log)
{
    ngx_int_t retval = NGX_ERROR;

    /* Check if we have Perl interpreter */
    if (psgilcf->perl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "Panic: NULL Perl interpreter");
        return retval;
    }

    /* Already have PSGI app */
    if (psgilcf->sub != NULL) {
        return NGX_OK;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, 0,
            "Loading app \"%s\"", psgilcf->app);

    /* Init PSGI application */
    {
        dSP;

        ENTER;
        SAVETMPS;

        PUSHMARK(SP);

        /* FIXME: This should be written way cleaner! */
        SV *call = newSVpvf("sub { return do '%s' }", psgilcf->app);

        SV *cvrv = eval_pv(SvPV_nolen(call), FALSE);

        int count = call_sv(cvrv, G_EVAL|G_SCALAR);

        if (SvTRUE(ERRSV))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "Failed to initialize psgi app \"%s\": %s", psgilcf->app, SvPV_nolen(ERRSV));
        } else if (count < 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "Application '%s' returned empty list", psgilcf->app);
        } else {
            SPAGAIN;
            psgilcf->sub =  (SV*)POPs;
            PUTBACK;

            /* Dereference */
            if (SvROK(psgilcf->sub)) {
                psgilcf->sub = SvRV(psgilcf->sub);
            }

            if (SvTYPE(psgilcf->sub) == SVt_PVCV || SvTYPE(psgilcf->sub) == SVt_PVMG) {
                SvREFCNT_inc(psgilcf->sub);

                ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, 0,
                        "Application successfully initialized: %s", SvPV_nolen(psgilcf->sub));
                retval = NGX_OK;
            } else {

                ngx_log_error(NGX_LOG_ERR, log, 0,
                        "psgi app \"%s\" returned something that is not a code reference: '%s'",
                        psgilcf->app, SvPV_nolen(psgilcf->sub));
            }
        }

        FREETMPS;
        LEAVE;
    }

    return retval;
}

ngx_int_t
ngx_http_psgi_perl_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_psgi_main_conf_t  *psgimcf =
        ngx_http_cycle_get_module_main_conf(cycle, ngx_http_psgi_module);

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
            "Init Perl interpreter in worker %d", ngx_pid);

    if (psgimcf) {

        dTHXa(psgimcf->perl);
        PERL_SET_CONTEXT(psgimcf->perl);

        /* FIXME: It looks very wrong.
         * Has new worker it's own Perl instance?
         * I think I should perl_clone() or something like that
         * Also $0 (script path) should be set somewhere.
         * I don't think it's right place for it. It should be done somewhere in local conf init stuff
         * Or, if many handlers share single Perl interpreter - before each handler call
         *
         * TODO
         * Test PID and related stuff
         * Test what happens if user try to change
         * Test what happens if user does 'fork' inside PSGI app
         */

        sv_setiv(GvSV(gv_fetchpv("$$", TRUE, SVt_PV)), (I32) ngx_pid);
    } else {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "PSGI panic: no main configuration supplied for init worker %d", ngx_pid);
        return NGX_ERROR;
    }

    return NGX_OK;
}

PerlInterpreter *
ngx_http_psgi_create_interpreter(ngx_conf_t *cf)
{
    int                n;
    PerlInterpreter   *perl;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "Create PSGI Perl interpreter");

    /* FIXME: Some code from ngx_http_perl_module.c I don't understand */
    if (ngx_set_environment(cf->cycle, NULL) == NULL) {
        return NULL;
    }

    perl = perl_alloc();

    if (perl == NULL) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
        return NULL;
    }

    {
        char *my_argv[] = { "", "-MIO::Handle", "-e", "0" };

        dTHXa(perl);
        PERL_SET_CONTEXT(perl);

        perl_construct(perl);

        n = perl_parse(perl, xs_init, 3, my_argv, NULL);

        if (n != 0) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, 3, "perl_parse() failed: %d", n);
            goto fail;
        }

        PerlIO_define_layer(aTHX_ PERLIO_FUNCS_CAST(&PerlIO_nginx_error));

    }

    return perl;

fail:

    (void) perl_destruct(perl);

    perl_free(perl);

    return NULL;
}

void
ngx_http_psgi_perl_exit(ngx_cycle_t *cycle)
{
    ngx_http_psgi_main_conf_t  *psgimcf =
        ngx_http_cycle_get_module_main_conf(cycle, ngx_http_psgi_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "psgi perl term");

    (void) perl_destruct(psgimcf->perl);

    perl_free(psgimcf->perl);

    PERL_SYS_TERM();
}

ngx_int_t
ngx_http_psgi_perl_call_psgi_callback(ngx_http_request_t *r)
{
    /* FIXME: Write actual code here */
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Call PSGI callback");

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "PSGI callback is not implemented yet");

    return NGX_ERROR;

}
