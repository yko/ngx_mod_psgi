#ifndef _NGX_HTTP_PSGI_RESPONSE_H_INCLUDED_
#define _NGX_HTTP_PSGI_RESPONSE_H_INCLUDED_
#include <EXTERN.h>
#include <perl.h>
#include "ngx_http_psgi_module.h"

ngx_int_t ngx_http_psgi_process_response(pTHX_ ngx_http_request_t *r, SV *response, PerlInterpreter *perl);
ngx_int_t ngx_http_psgi_process_array_response(pTHX_ ngx_http_request_t *r, SV *response);
ngx_int_t ngx_http_psgi_process_headers(pTHX_ ngx_http_request_t *r, SV *headers, SV *status);
ngx_int_t ngx_http_psgi_process_body(pTHX_ ngx_http_request_t *r, SV *body);
ngx_int_t ngx_http_psgi_process_body_array(pTHX_ ngx_http_request_t *r, AV *body);
ngx_int_t ngx_http_psgi_process_body_glob(pTHX_ ngx_http_request_t *r, GV *body);

ngx_int_t chain_buffer(ngx_http_request_t *r, u_char *p, STRLEN len, ngx_chain_t **first, ngx_chain_t **last);
ngx_int_t ngx_sv2str(ngx_http_request_t *r, ngx_str_t *dst, u_char* src, int len);

#endif

