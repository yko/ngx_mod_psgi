#include "ngx_http_psgi_error_stream.h"
#include "ngx_http_psgi_module.h"

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
    return 0;
}

PERLIO_FUNCS_DECL(PerlIO_nginx_error) = {
    sizeof(PerlIO_funcs),
    "nginx_error",
    sizeof(PerlIONginxError),
    PERLIO_K_RAW,
    PerlIOBase_pushed,
    NULL, //PerlIONginxError_popped,
    NULL, //PerlIONginxError_open,
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

SV *PerlIONginxError_newhandle(ngx_http_request_t *r)
{
    /*
     * TODO: I need better error handling here
     */

    ngx_log_t *log = r->connection->log;

    IO* io;
    GV *gv;
    PerlIO *f = PerlIO_allocate(aTHX); // FIXME: RLY allocate?
    gv = (GV*)SvREFCNT_inc(newGVgen("Nginx::PSGI::errors"));

    io = GvIOn(gv);
    if (gv)
        (void) hv_delete(GvSTASH(gv), GvNAME(gv), GvNAMELEN(gv), G_DISCARD);

    // Kinda bless
    if ( (f = PerlIO_push(aTHX_ f, PERLIO_FUNCS_CAST(&PerlIO_nginx_error), NULL, NULL)) ) {
        PerlIOBase(f)->flags = PERLIO_F_CANWRITE | PERLIO_F_OPEN;
        PerlIONginxError *st = PerlIOSelf(f, PerlIONginxError);
        IoOFP(io) = f;
        IoTYPE(io) = IoTYPE_WRONLY;
        st->log = log;

    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "Error pushing NginxError layer to FH"
                );
        return NULL;
    }

    return newRV_inc((SV *)gv);
}
