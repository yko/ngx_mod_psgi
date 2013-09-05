#include "ngx_http_psgi_writer.h"
#include "ngx_http_psgi_response.h"
#include <ngx_http.h>

XS(Nginx__PSGI__Writer__write) {
    dXSARGS;

    if (items != 2) {
        croak("Usage: $writer->write($content);");
    }

    ngx_http_request_t *r;
    if ( sv_isobject(ST(0)) && (SvTYPE(SvRV(ST(0))) == SVt_PVMG) ) {
        r = (ngx_http_request_t *)SvIV((SV*)SvRV(ST(0)));
    }
    else {
        croak( "Nginx::PSGI::Writer->write() -- THIS not a blessed SV reference" );
    }
    u_char              *p = NULL;
    STRLEN               len;
    p = (u_char*)SvPV(ST(1), len);
    ngx_chain_t   *first_chain = NULL;
    ngx_chain_t   *last_chain = NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "PSGI writer write %i bytes: '%s'", len, p);

    chain_buffer(r, p, len, &first_chain, &last_chain);

    first_chain->buf->last_buf = 0;
    first_chain->buf->last_in_chain = 1;
    ngx_http_output_filter(r, first_chain);

}

XS(Nginx__PSGI__Writer__close) {
    dXSARGS;

    if (items != 1) {
        croak("Usage: $writer->close();");
    }

    ngx_http_request_t *r;
    if ( sv_isobject(ST(0)) && (SvTYPE(SvRV(ST(0))) == SVt_PVMG) ) {
        r = (ngx_http_request_t *)SvIV((SV*)SvRV(ST(0)));
    }
    else {
        croak( "Nginx::PSGI::Writer->close() -- THIS not a blessed SV reference" );
    }

    ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
    out->buf = ngx_calloc_buf(r->pool);
    out->buf->sync = 1;
    out->buf->last_buf = 1;

    ngx_http_output_filter(r, out);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "PSGI writer close");

    ngx_http_finalize_request(r, NGX_OK);
}
