#ifndef _NGX_HTTP_PSGI_PERL_H_INCLUDED_
#define _NGX_HTTP_PSGI_PERL_H_INCLUDED_
#include <EXTERN.h>
#include <perl.h>
#include "ngx_http_psgi_module.h"

SV *ngx_http_psgi_create_env(pTHX_ ngx_http_request_t *r, char *app);

ngx_int_t ngx_http_psgi_perl_init_worker(ngx_cycle_t *cycle);
ngx_int_t ngx_http_psgi_init_app(pTHX_ ngx_http_psgi_loc_conf_t *psgilcf, ngx_log_t *log);

PerlInterpreter *ngx_http_psgi_create_interpreter(ngx_conf_t *cf);

ngx_int_t ngx_http_psgi_perl_handler(ngx_http_request_t *r, ngx_http_psgi_loc_conf_t *psgilcf, void *interpreter);

void ngx_http_psgi_perl_exit(ngx_cycle_t *cycle);

ngx_int_t ngx_http_psgi_perl_call_psgi_callback(ngx_http_request_t *r);
#endif
