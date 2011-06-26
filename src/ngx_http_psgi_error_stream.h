#ifndef NGX_PERLIO_ERROR
#define NGX_PERLIO_ERROR
#include <EXTERN.h>               /* from the Perl distribution     */
#include <perl.h>                 /* from the Perl distribution     */
#include "perliol.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

typedef struct {
    struct _PerlIO base;
    ngx_log_t *log;
} PerlIONginxError;

IV
PerlIONginxError_pushed(pTHX_ PerlIO * f, const char *mode, SV * arg,
        PerlIO_funcs * tab);

PerlIO *
PerlIONginxError_open(pTHX_ PerlIO_funcs * self, PerlIO_list_t * layers, IV n,
		  const char *mode, int fd, int imode, int perm,
		  PerlIO * f, int narg, SV ** args);


PerlIO_funcs PerlIO_nginx_error;

SV *PerlIONginxError_newhandle(ngx_http_request_t *r);

#endif

