#ifndef _NGX_HTTP_PSGI_MODULE_H_INCLUDED_
#define _NGX_HTTP_PSGI_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <EXTERN.h>
#include <perl.h>

typedef ngx_http_request_t   *nginx;

extern ngx_module_t  ngx_http_psgi_module;

typedef struct {
    PerlInterpreter   *perl;
} ngx_http_psgi_main_conf_t;

typedef struct {
    SV                *sub;
    SV                *app;
    PerlInterpreter   *perl;
} ngx_http_psgi_loc_conf_t;

typedef struct {
    SV                       *app;
    SV                       *env;
    SV                       *input;
    SV                       *errors;
    SV                       *callback;
    SV                       *responder;
    SV                       *writer;
    PerlInterpreter          *perl;
} ngx_http_psgi_ctx_t;

void *ngx_http_psgi_create_main_conf(ngx_conf_t *cf);
char *ngx_http_psgi_init_main_conf(ngx_conf_t *cf, void *conf);
void *ngx_http_psgi_create_loc_conf(ngx_conf_t *cf);
char *ngx_http_psgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
char *ngx_http_psgi(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_psgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t ngx_http_psgi_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_psgi_init_worker(ngx_cycle_t *cycle);
char *ngx_http_psgi_init_interpreter(ngx_conf_t *cf, ngx_http_psgi_main_conf_t *psgimcf);
char *ngx_http_psgi(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

void ngx_http_psgi_handler_with_body(ngx_http_request_t *r);
void ngx_http_psgi_exit(ngx_cycle_t *cycle);


/*
 * workaround for "unused variable `Perl___notused'" warning
 * when building with perl 5.6.1
 */
#ifndef PERL_IMPLICIT_CONTEXT
#undef  dTHXa
#define dTHXa(a)
#endif

#endif /* _NGX_HTTP_PERL_MODULE_H_INCLUDED_ */
