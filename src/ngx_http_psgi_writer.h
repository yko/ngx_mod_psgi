#ifndef _NGX_HTTP_PSGI_WRITER_H_INCLUDED_
#define _NGX_HTTP_PSGI_WRITER_H_INCLUDED_
#include <EXTERN.h>
#include <perl.h>
#include "XSUB.h"

XS(Nginx__PSGI__Writer__write);
XS(Nginx__PSGI__Writer__close);

#endif
