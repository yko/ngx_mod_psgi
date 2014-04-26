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

    len = len > (off_t)count ? (off_t)count : len;

    Copy(r->request_body->bufs->buf->pos + st->pos, vbuf, len, STDCHAR);

    st->pos+= len;
    return len;
}

PERLIO_FUNCS_DECL(PerlIO_nginx_input) = {
    sizeof(PerlIO_funcs),
    "ngx_input",
    sizeof(PerlIONginxInput),
    PERLIO_K_RAW,
    NULL, //PerlIOBase_pushed,
    NULL, //PerlIONginxInput_popped,
    PerlIONginxInput_open,
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

SV *PerlIONginxInput_newhandle(pTHX_ ngx_http_request_t *r)
{
    ngx_log_t *log = r->connection->log;

    GV *gv = (GV*)SvREFCNT_inc(newGVgen("Nginx::PSGI::Input"));
    if (!gv)
        return &PL_sv_undef;

    (void) hv_delete(GvSTASH(gv), GvNAME(gv), GvNAMELEN(gv), G_DISCARD);

    /* Body in memory */
    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "Open filehandle with 'ngx_input' layer to read from buffers");

        PerlIO *f = PerlIO_allocate(aTHX);

        if (!(f = PerlIO_push(aTHX_ f, PERLIO_FUNCS_CAST(&PerlIO_nginx_input), "<", NULL)) ) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "Error pushing layer to FH"
                    );
            return &PL_sv_undef;
        }

        if (!do_open(gv, "+<&", 3, FALSE, O_RDONLY, 0, f)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "Error opening GV"
                    );
            // FIXME PerlIO_close
            return &PL_sv_undef;
        }

        PerlIONginxInput *st = PerlIOSelf(f, PerlIONginxInput);
        st->r = r;

    } else {
        /* Body in temp file */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "Open PSGI request body temp file '%s'",
                r->request_body->temp_file->file.name.data
                );
        bool result = do_open(gv,(char*)r->request_body->temp_file->file.name.data, r->request_body->temp_file->file.name.len,FALSE,O_RDONLY,0,NULL);

        if (!result) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                    "Error opening file"
                    );
            // FIXME PerlIO_close
            return NULL;

        }
    }

    return (SV*)newRV_noinc((SV *)gv);
}
