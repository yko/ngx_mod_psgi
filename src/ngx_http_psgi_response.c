#include "ngx_http_psgi_response.h"
#include "ngx_http_psgi_perl.h"

ngx_int_t
ngx_http_psgi_process_response(pTHX_ ngx_http_request_t *r, SV *response, PerlInterpreter *perl)
{

    if (SvROK(response))
        response = SvRV(response);

    if (SvTYPE(response) == SVt_PVCV || SvTYPE(response) == SVt_PVMG) {
        ngx_http_psgi_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_psgi_module);
        if (ctx == NULL) {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_psgi_module));
            if (ctx == NULL) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                        "PSGI panic: no psgi context found while processing response");
                return NGX_ERROR;
            }

            ngx_http_set_ctx(r, ctx, ngx_http_psgi_module);
        }
        ctx->callback = response;
        SvREFCNT_inc(ctx->callback);
        return ngx_http_psgi_perl_call_psgi_callback(r);
    }

    // Response should be reference to ARRAY
    if (SvTYPE(response) != SVt_PVAV) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "PSGI app returned wrong value: %s",  SvPV_nolen(response));

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create chained response from ARRAY:
     * convert each array element to buffer
     * and pass to filter
     */

    AV *psgir = (AV*)response;

    // Array should contain at least 3 elements
    if (av_len(psgir) < 2) {
        ngx_http_psgi_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_psgi_module);
        if (!ctx->callback || av_len(psgir) < 1) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "PSGI app returned array with wrong length: %d",  av_len(psgir));

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // Process HTTP status code
    SV **http_status = av_fetch(psgir, 0, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "PSGI app returned status code: %d",  SvIV(http_status[0]));

    // Process headers
    SV **headers = av_fetch(psgir, 1, 0);

    if (ngx_http_psgi_process_headers(aTHX_ r, *headers, *http_status) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Failed to process PSGI response headers");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Process body


    SV **body = av_fetch(psgir, 2, 0);
    return ngx_http_psgi_process_body(aTHX_ r, *body);

}

ngx_int_t
ngx_http_psgi_process_headers(pTHX_ ngx_http_request_t *r, SV *headers, SV *status)
{

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "Process PSGI headers");

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

    for (i = 0; i <= len; i+=2) {
        if (i + 1 > len)
            break;

        SV **header = av_fetch(h, i, 0);
        u_char  *key, *value;
        STRLEN klen, vlen;
        key = (u_char *) SvPV(header[0], klen);
        value = (u_char *) SvPV(header[1], vlen);

        if (ngx_strncasecmp(key, (u_char *)"CONTENT-TYPE", klen) == 0) {

            r->headers_out.content_type.data = ngx_pnalloc(r->pool, vlen);
            if (r->headers_out.content_type.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "In PSGI response: header 'Content-Type' not defined");
                return NGX_ERROR;
            }
            r->headers_out.content_type.len = vlen;
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
    return NGX_OK;
}

ngx_int_t
ngx_http_psgi_process_body(pTHX_ ngx_http_request_t *r, SV *body)
{

    /* If response object is something blessed (even ARRAYref)
     * than we consider it as IO::Handle-like object according to PSGI spec.
     * Thanks to au on #plack
     */

    if (!SvROK(body)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "PSGI app should return body as reference to something, but returned: %s",  SvPV_nolen(body));
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    body = SvRV(body);

    switch (SvTYPE(body)) {
        case SVt_PVAV:
            return ngx_http_psgi_process_body_array(aTHX_ r, (AV*)body);

        case SVt_PVMG:
        case SVt_PVGV:
            return ngx_http_psgi_process_body_glob(aTHX_ r, (GV*)body);

        default:
            ngx_log_error(
                    NGX_LOG_ERR, r->connection->log, 0,
                    "PSGI app returned body of unsupported type: %s",
                    SvPV_nolen(body));

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

ngx_int_t
ngx_http_psgi_process_body_glob(pTHX_ ngx_http_request_t *r, GV *body)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "PSGI app returned filehandle: %s", SvPV_nolen(newRV((SV*)body)));

    ngx_chain_t   *first_chain = NULL;
    ngx_chain_t   *last_chain  = NULL;
    bool data = 1;

    /* TODO: Call $body->close when done
     * TODO: Support sendfile option
     * FIXME: This sucks. Push handle to stack and loop readline, save time
     * FIXME: This sucks. Do async event-based writing
     * FIXME: This sucks. Readline can return lines 1-10 bytes long. Buffer data instead of chaining each line
     */

    while (data) {
        dSP;
        ENTER;
        SAVETMPS;

        PUSHMARK(SP);
        XPUSHs(newRV((SV*)body));
        PUTBACK;

        call_method("getline", G_SCALAR);

        SPAGAIN;

        SV *buffer = POPs;

        if (SvTRUE(ERRSV))
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "Error reading from FH: %s", SvPV_nolen(ERRSV));
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else if (!SvOK(buffer)) {
            /* FIXME: This sounds wrong. I think I should check for eof */
            data = 0;
        } else {
            u_char              *p = NULL;
            STRLEN               len;
            p = (u_char*)SvPV(buffer, len);

            if (chain_buffer(r, p, len, &first_chain, &last_chain) != NGX_OK) {
                ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "Error chaining psgi response buffer");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        PUTBACK;
        FREETMPS;
        LEAVE;
    }

    if (first_chain == NULL)
        return NGX_DONE;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "Reached end of PSGI response filehandle");

    ngx_http_output_filter(r, first_chain);
    return NGX_OK;
}

ngx_int_t
ngx_http_psgi_process_body_array(pTHX_ ngx_http_request_t *r, AV *body)
{
    int len = av_len((AV*)body);
    int i;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "PSGI app returned %d body chunks", len + 1);

    ngx_chain_t   *first_chain = NULL, *last_chain = NULL;

    if (len < 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "PSGI app returned zerro-elements body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i <= len; i++) {
        u_char              *p;
        STRLEN               plen;

        SV **body_chunk = av_fetch(body, i, 0);

        p = (u_char *) SvPV(*body_chunk, plen);

        if (!plen)
            continue;

        if (chain_buffer(r, p, plen, &first_chain, &last_chain) != NGX_OK) {
            ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Error chaining psgi response buffer");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (first_chain == NULL) {
        return NGX_DONE;
    }

    ngx_http_output_filter(r, first_chain);
    return NGX_OK;
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

ngx_int_t
chain_buffer(ngx_http_request_t *r, u_char *p, STRLEN len, ngx_chain_t **first, ngx_chain_t **last)
{
    ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
    if (out == NULL)
        return NGX_ERROR;

    ngx_buf_t    *b = ngx_calloc_buf(r->pool);
    if (b == NULL)
        return NGX_ERROR;

    b->pos = b->start = ngx_palloc(r->pool, len);
    ngx_memcpy(b->pos, p, len);
    b->end = b->last = b->start + len;
    b->memory = 1;
    b->last_buf = 1;

    out->buf = b;
    out->next = NULL;

    if (*first == NULL) {
        *first = out;
    }
    if (*last != NULL) {
        (*last)->buf->last_buf = 0;
        (*last)->next = out;
    }
    *last = out;

    return NGX_OK;
}
