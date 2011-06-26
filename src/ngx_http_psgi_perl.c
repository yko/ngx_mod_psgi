#include "ngx_http_psgi_perl.h"
#include "ngx_http_psgi_error_stream.h"
#include "ngx_http_psgi_input_stream.h"
EXTERN_C void xs_init (pTHX);

SV *ngx_http_psgi_create_env(ngx_http_request_t *r, SV *app)
{
    ngx_list_part_t        *part;
    ngx_table_elt_t        *h;
    ngx_uint_t              i, c, x;


    SV  *_version[2];
    AV  *version;

    HV* env = newHV();

    // PSGI version 1.0, arrayref [1,0]
    _version[0] = newSViv(1);
    _version[1] = newSViv(0);
    version = av_make(2, _version);


    hv_store(env, "psgi.version", sizeof("psgi.version")-1, newRV_inc((SV*)version), 0);
    // FIXME: pass right url_scheme
    hv_store(env, "psgi.url_scheme", sizeof("psgi.url_scheme")-1, newSVpv("http", 0), 0);

    /* FIXME: after any of this two operations $! is set to 'Inappropriate ioctl for device' */
    hv_store(env, "psgi.errors", sizeof("psgi.errors")-1, PerlIONginxError_newhandle(r), 0);
    hv_store(env, "psgi.input", sizeof("psgi.input")-1, PerlIONginxInput_newhandle(r), 0);

    hv_store(env, "REQUEST_METHOD", sizeof("REQUEST_METHOD")-1, newSVpv((char *)r->method_name.data, r->method_name.len), 0);
    hv_store(env, "SCRIPT_NAME", sizeof("SCRIPT_NAME")-1, app, 0);
    hv_store(env, "QUERY_STRING", sizeof("QUERY_STRING")-1, newSVpv((char *)r->args.data, r->args.len), 0);
    // FIXME: Send real hostname
    hv_store(env, "SERVER_NAME", sizeof("SERVER_NAME")-1, newSVpv("127.0.0.1", 9), 0);
    hv_store(env, "REMOTE_ADDR", sizeof("REMOTE_ADDR")-1, newSVpv((char *)r->connection->addr_text.data, r->connection->addr_text.len), 0);
    /* TODO
     *
     * PATH_INFO
     * REQUEST_URI
     * SERVER PORT
     * SERVER_NAME should be actual hostname!
     * SERVER_PROTOCOL
     * psgi.multithread
     * psgi.multiprocess
     * CONTENT_LENGTH
     * CONTENT_TYPE
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
        x = h[i].key.len + sizeof("HTTP_");
        while (x > 0) {
            if (name.data[x] == '-') {
                name.data[x] = '_';
            }
            x--;
        }
        hv_store(env, (char *)name.data, sizeof("HTTP_") + h[i].key.len - 1, newSVpv((char *)h[i].value.data, h[i].value.len), 0);
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

    if (psgilcf->sub == NULL) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                "Loading PSGI app \"%s\"",
                SvPV_nolen(psgilcf->app));

        if(ngx_http_psgi_init_app(psgilcf, log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "Running PSGI app \"%s\"",
            SvPV_nolen(psgilcf->app));

    {
        int count;

        dTHXa(perl);
        PERL_SET_CONTEXT(perl);

        SV *env = ngx_http_psgi_create_env(r, psgilcf->app);

        dSP;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);

        XPUSHs(sv_2mortal(env));

        PUTBACK;

        count = call_sv(psgilcf->sub, G_EVAL|G_SCALAR);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                "PSGI app response: %d elements", count);

        SPAGAIN;

        if (SvTRUE(ERRSV))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "PSGI handler execution failed: %s", SvPV_nolen(ERRSV));

            POPs;
        }
        else if (count < 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "PSGI app \"%V\" did not returned value", psgilcf->app, SvPV_nolen(ERRSV));
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                    "Processing PSGI app response, %d elements", count);

            retval = ngx_http_psgi_process_response(r, POPs, perl);
        }

        PUTBACK;
        FREETMPS;
        LEAVE;
    }
    return retval;
}

ngx_int_t
ngx_http_psgi_init_app(ngx_http_psgi_loc_conf_t *psgilcf, ngx_log_t *log)
{
    ngx_int_t retval = NGX_ERROR;

    // Check if we have Perl interpreter
    if (psgilcf->perl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "Panic: NULL Perl interpreter");
        return retval;
    }

    // Already have PSGI app
    if (psgilcf->sub != NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "Loading app \"%s\"", SvPV_nolen(psgilcf->app));

    // Try to init PSGI application
    {
        dTHXa(psgilcf->perl);
        PERL_SET_CONTEXT(psgilcf->perl);


        dSP;

        ENTER;
        SAVETMPS;

        PUSHMARK(SP);

        SV *call = newSVpvf(aTHX_ "sub { return do '%s' }", SvPV_nolen(psgilcf->app));

        SV *cvrv = eval_pv(SvPV_nolen(call), FALSE);

        int count = call_sv(cvrv, G_EVAL|G_SCALAR);

        if (SvTRUE(ERRSV))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "Failed to initialize psgi app \"%s\": %s", SvPV_nolen(psgilcf->app), SvPV_nolen(ERRSV));
        } else if (count < 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "Application '%s' returned empty list", psgilcf->app);
        } else {
            // TODO: Check if returned value isa coderef
            //
            SPAGAIN;
            psgilcf->sub =  newRV_inc((SV*)POPi);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                    "Application successfully initialized: %s", SvPV_nolen(psgilcf->sub));

            retval = NGX_OK;
            PUTBACK;
        }

        FREETMPS;
        LEAVE;
    }

    return retval;
}

ngx_int_t
ngx_http_psgi_process_response(ngx_http_request_t *r, SV *response, PerlInterpreter *perl)
{

    dTHXa(perl);
    PERL_SET_CONTEXT(perl);

    // response isa ARRAYREF

    // Response should be reference to ARRAY
    if (!SvROK(response) || SvTYPE(SvRV(response)) != SVt_PVAV) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "PSGI app returned wrong value: %s",  SvPV_nolen(response));

        return NGX_ERROR;
    }

    /* Create chained response from ARRAY:
     * convert each array element to buffer
     * and pass to filter
     */

    AV *psgir = (AV*)SvRV(response);

    // Array should contain at least 3 elements
    if (av_len(psgir) < 2) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "PSGI app returned array with wrong length: %d",  av_len(psgir));

        return NGX_ERROR;
    }

    // Process HTTP status code
    SV **http_status = av_fetch(psgir, 0, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "PSGI app returned status code: %d",  SvIV(http_status[0]));

    // Process headers
    SV **headers = av_fetch(psgir, 1, 0);

    if (ngx_http_psgi_process_headers(r, headers[0], http_status[0]) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Failed to process PSGI response headers");
        return NGX_ERROR;
    }

    // Process body

    // TODO: According to PSGI spec body can be IO::Handle
    // I should handle it correct

    // If response object is something blessed (even ARRAYref) than we consider it as
    // IO::Handle-like object according to PSGI spec
    // Thanks to au on #plack

    SV **body = av_fetch(psgir, 2, 0);

    // Threat body as an ARRAYref
    int len = av_len((AV*)SvRV(body[0]));
    int i;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "PSGI app returned %d body chunks", len);

    ngx_chain_t   *first_chain = NULL;
    ngx_chain_t   *last_chain = NULL;
    ngx_buf_t    *last_buffer = NULL;

    for (i = 0; i <= len; i++) {
        u_char              *p;
        STRLEN               plen;
        ngx_buf_t    *b;
        ngx_chain_t *out;
        out = ngx_alloc_chain_link(r->pool);
        if (out == NULL)
            return NGX_ERROR;

        SV **body_chunk = av_fetch((AV*)SvRV(body[0]), i, 0);
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

        if (b == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                    "Failed to allocate response buffer.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        p = (u_char *) SvPV(body_chunk[0], plen);
        b->pos = b->start = ngx_pnalloc(r->pool, plen);
        ngx_memcpy(b->start, p, plen);
        b->end = b->last = b->start + plen;
        b->memory = 1;
        b->last_buf = 1;

        out->buf = b;
        out->next = NULL;

        if (first_chain == NULL) {
            first_chain = out;
        }
        if (last_chain != NULL) {
            last_chain->buf->last_buf = 0;
            last_chain->next = out;
        }
        last_chain = out;
        last_buffer = b;
    }

    return ngx_http_output_filter(r, first_chain);

}

ngx_int_t
ngx_http_psgi_perl_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_psgi_main_conf_t  *psgimcf =
        ngx_http_cycle_get_module_main_conf(cycle, ngx_http_psgi_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
            "Init Perl interpreter in worker %d", ngx_pid);

    if (psgimcf) {

        dTHXa(psgimcf->perl);
        PERL_SET_CONTEXT(psgimcf->perl);

        /* set worker's $$ */

        // FIXME: It looks very wrong.
        // Has new worker it's own Perl instance?
        // I think I should perl_clone() or something like that
        // Also $0 (script path) should be set somewhere.
        // I don't think it's right place for it. It should be done somewhere in local conf init stuff
        // Or, if many handlers share single Perl interpreter - before each handler call.
//        sv_setiv(GvSV(gv_fetchpv("$", TRUE, SVt_PV)), (I32) ngx_pid);
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "Create PSGI Perl interpreter");

    // FIXME: WTF? Some code from ngx_http_perl_module.c I don't understand
    if (ngx_set_environment(cf->cycle, NULL) == NULL) {
        return NULL;
    }

    perl = perl_alloc();

    if (perl == NULL) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
        return NULL;
    }

    {
        // Init very empty Perl interpreter
        // TODO: Should I load IO::Handle here with -MIO::Handle?
        char *my_argv[] = { "", "-e", "0" };

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

ngx_int_t
ngx_http_psgi_process_headers(ngx_http_request_t *r, SV *headers, SV *status)
{

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "process headers");

    if (r->headers_out.status == 0) {
        r->headers_out.status = SvIV(status);
    }

    if (!SvROK(headers) || SvTYPE(SvRV(headers)) != SVt_PVAV) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "PSGI app returned wrong headers: %s",  SvPV_nolen(headers));
        return NGX_ERROR;
    }

    AV *h = (AV *)SvRV(headers);

    int len = av_len(h);
    int i;

    if (!(len % 2)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Even number of header-value elements: %i. Possible error.", len);
    }

    for (i = 0; i <= len; i++) {
        // FIXME WTF: something very wrong here with headers length
        if (i + 1 > len)
            break;

        SV **header = av_fetch(h, i, 0);
        u_char  *key, *value;
        STRLEN klen, vlen;
        key = (u_char *) SvPV(header[0], klen);
        value = (u_char *) SvPV(header[1], vlen);

        if (ngx_strncasecmp(key, (u_char *)"CONTENT-TYPE", klen) == 0) {

            r->headers_out.content_type.len = vlen;
            r->headers_out.content_type.data = ngx_pnalloc(r->pool, vlen);
            if (r->headers_out.content_type.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(r->headers_out.content_type.data, value, vlen);
        } else {
            ngx_table_elt_t     *header_ent;

            header_ent = ngx_list_push(&r->headers_out.headers);

            header_ent->hash = 1;
            if (header_ent == NULL) {
                return NGX_ERROR;
            }

            if (ngx_sv2str(r, &header_ent->key, key, klen) != NGX_OK) {
                return NGX_ERROR;
            }

            if (ngx_sv2str(r, &header_ent->value, value, vlen) != NGX_OK) {
                return NGX_ERROR;
            }
        }

    }

    ngx_http_send_header(r);
    return NGX_DONE;
}

ngx_int_t
ngx_sv2str(ngx_http_request_t *r, ngx_str_t *dst, u_char* src, int len)
{
    dst->data = ngx_pnalloc(r->pool, len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    dst->len = len;
    ngx_memcpy(dst->data, src, len);
        return NGX_OK;
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
