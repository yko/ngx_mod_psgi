#include "ngx_http_psgi_error_stream.h"

PerlIO *
PerlIONginxError_open(pTHX_ PerlIO_funcs * self, PerlIO_list_t * layers, IV n,
        const char *mode, int fd, int imode, int perm,
        PerlIO * f, int narg, SV ** args)
{
    die("NginxError layer can not be assigned from Perl land");

    return NULL;
}

IV
PerlIONginxError_fileno(pTHX_ PerlIO * f)
{
    PERL_UNUSED_ARG(f);
    return -1; // I'm kinda socket.
}

SSize_t
PerlIONginxError_write(pTHX_ PerlIO * f, const void *vbuf, Size_t count)
{
    PerlIONginxError *st = PerlIOSelf(f, PerlIONginxError);

    // I need to quote '%' characters or disable printf in logging somehow
    ngx_log_error(NGX_LOG_ERR, st->log, 0,
            "%s", (const char *)vbuf);

    return count;
}

PERLIO_FUNCS_DECL(PerlIO_nginx_error) = {
    sizeof(PerlIO_funcs),
    "ngx_error",
    sizeof(PerlIONginxError),
    PERLIO_K_RAW,
    NULL, // PerlIONginxError_pushed,
    NULL, // PerlIONginxError_popped,
    PerlIONginxError_open,
    NULL, //PerlIOBase_binmode,
    NULL, //PerlIONginxError_arg,
    PerlIONginxError_fileno,
    NULL, //PerlIONginxError_dup,
    NULL, //PerlIONginxError_read,
    NULL, /* unread */
    PerlIONginxError_write,
    NULL, //PerlIONginxError_seek,
    NULL, //PerlIONginxError_tell,
    NULL, //PerlIONginxError_close,
    NULL, //PerlIONginxError_flush,
    NULL, //PerlIONginxError_fill,
    NULL, //PerlIOBase_eof,
    NULL, //PerlIOBase_error,
    NULL, //PerlIOBase_clearerr,
    NULL, //PerlIOBase_setlinebuf,
    NULL, //PerlIONginxError_get_base,
    NULL, //PerlIONginxError_bufsiz,
    NULL, //PerlIONginxError_get_ptr,
    NULL, //PerlIONginxError_get_cnt,
    NULL, //PerlIONginxError_set_ptrcnt,
};

SV *PerlIONginxError_newhandle(pTHX_ ngx_http_request_t *r)
{
    GV *gv = (GV*)SvREFCNT_inc(newGVgen("Nginx::PSGI::Error"));
    if (!gv)
        return &PL_sv_undef;

    (void) hv_delete(GvSTASH(gv), GvNAME(gv), GvNAMELEN(gv), G_DISCARD);
    PerlIO *f = PerlIO_allocate(aTHX);

    if (!(f = PerlIO_push(aTHX_ f, PERLIO_FUNCS_CAST(&PerlIO_nginx_error), ">", NULL)) ) {
         return &PL_sv_undef;
    }

    if (!do_open(gv, "+>&", 3, FALSE, O_WRONLY, 0, f)) {
        return &PL_sv_undef;
    }

    PerlIONginxError *st = PerlIOSelf(f, PerlIONginxError);
    st->log = r->connection->log;

    return newRV_noinc((SV*)gv);
}
