#include <EXTERN.h>
#include <perl.h>
#include "ngx_http_psgi_writer.h"

EXTERN_C void xs_init (pTHX);

EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

EXTERN_C void
xs_init(pTHX)
{
	char *file = __FILE__;
	dXSUB_SYS;

	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
	newXS("Nginx::PSGI::Writer::write", Nginx__PSGI__Writer__write, file);
	newXS("Nginx::PSGI::Writer::close", Nginx__PSGI__Writer__close, file);
}
