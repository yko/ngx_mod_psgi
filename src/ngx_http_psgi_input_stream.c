#include "ngx_http_psgi_input_stream.h"
#include "ngx_http_psgi_module.h"

PerlIO *
PerlIONginxInput_open(pTHX_ PerlIO_funcs * self, PerlIO_list_t * layers, IV n,
        const char *mode, int fd, int imode, int perm,
        PerlIO * f, int narg, SV ** args)
{
    die("NginxInput layer can not be assigned from Perl land");

    return NULL;
}

IV
PerlIONginxInput_fileno(pTHX_ PerlIO * f)
{
    PERL_UNUSED_ARG(f);
    return -1; // I'm kinda socket.
}


IV
PerlIONginxInput_eof(pTHX_ PerlIO *f)
{

    PerlIONginxInput *st = PerlIOSelf(f, PerlIONginxInput);

    if (st->r->headers_in.content_length_n <= st->pos) {
        return 1;
    }
    return 0;
}

SSize_t
PerlIONginxInput_read(pTHX_ PerlIO *f, void *vbuf, Size_t count)
{
    PerlIONginxInput *st = PerlIOSelf(f, PerlIONginxInput);
    ngx_http_request_t *r = st->r;

    if (r->request_body == NULL
            || r->request_body->temp_file
            || r->request_body->bufs == NULL)
    {
        return 0;
    }

    off_t len = r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos - st->pos;

    if (len == 0) {
        return 0;
    }

    len = len > count ? count : len;

    Copy(r->request_body->bufs->buf->pos + st->pos, vbuf, len, STDCHAR);

    st->pos+= len;
    return len;
}

PERLIO_FUNCS_DECL(PerlIO_nginx_input) = {
    sizeof(PerlIO_funcs),
    "nginx_input",
    sizeof(PerlIONginxInput),
    PERLIO_K_RAW,
    PerlIOBase_pushed,
    NULL, //PerlIONginxInput_popped,
    NULL, //PerlIONginxInput_open,
    NULL, //PerlIOBase_binmode,
    NULL, //PerlIONginxInput_arg,
    PerlIONginxInput_fileno,
    NULL, //PerlIONginxInput_dup,
    PerlIONginxInput_read,
    NULL, /* unread */
    NULL, // PerlIONginxInput_write,
    NULL, //PerlIONginxInput_seek,
    NULL, //PerlIONginxInput_tell,
    NULL, //PerlIONginxInput_close,
    NULL, //PerlIONginxInput_flush,
    NULL, //PerlIONginxInput_fill,
    NULL, //PerlIONginxInput_eof, //PerlIOBase_eof,
    NULL, //PerlIOBase_error,
    NULL, //PerlIOBase_clearerr,
    NULL, //PerlIOBase_setlinebuf,
    NULL, //PerlIONginxInput_get_base,
    NULL, //PerlIONginxInput_bufsiz,
    NULL, //PerlIONginxInput_get_ptr,
    NULL, //PerlIONginxInput_get_cnt,
    NULL, //PerlIONginxInput_set_ptrcnt,
};

SV *PerlIONginxInput_newhandle(ngx_http_request_t *r)
{
    /*
     * TODO: I need better error handling here
     */

    ngx_log_t *log = r->connection->log;

    PerlIO *f;
    IO* io;
    GV *gv;

    f = PerlIO_tmpfile(aTHX);
    gv = (GV*)SvREFCNT_inc(newGVgen("Nginx::PSGI::input"));
    io = GvIOn(gv);

    if (gv)
        (void) hv_delete(GvSTASH(gv), GvNAME(gv), GvNAMELEN(gv), G_DISCARD);

    // Apply layer
    if ( (f = PerlIO_push(aTHX_ f, PERLIO_FUNCS_CAST(&PerlIO_nginx_input), NULL, NULL)) ) {
        PerlIONginxInput *st = PerlIOSelf(f, PerlIONginxInput);
        st->r = r;
        IoIFP(io) = f;
        PerlIOBase(f)->flags = PERLIO_F_CANREAD | PERLIO_F_OPEN;
        IoTYPE(io) = IoTYPE_RDONLY;
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                "Error pushing layer to FH"
                );
        return NULL;
    }

    return (SV*)newRV_inc((SV *)gv);
}
