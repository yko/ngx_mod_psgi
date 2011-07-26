NGX_VERSION = 1.0.4
HOME = ${CURDIR}
NGX_DIST = nginx-${NGX_VERSION}.tar.gz
NGX_DIR = ${CURDIR}/nginx-${NGX_VERSION}
NGX_MAKE = ${NGX_DIR}/Makefile
TMP_CONF = ${HOME}/tmp/nginx.conf
TMP_CONF_TEMPLATE = ${HOME}/eg/nginx.conf
PIDFILE = ${HOME}/tmp/nginx.pid

default: build

build: ${NGX_MAKE} dirs
	make -C ${NGX_DIR} 

test: build
	prove -lrv

try: kill build configs
	@${NGX_DIR}/objs/nginx
	@echo Sending simple request with body: \"Client request body\"
	@echo Answer:
	@echo
	curl http://127.0.0.1:3000/ -d "Client request body" -D -

clean: kill
	@rm       ${HOME}/log/* 2>1 /dev/null || echo clean
	@rm   -r  ${HOME}/tmp/* 2>1 /dev/null || echo clean

realclean: clean
	@if [ -f "${NGX_DIR}/Makefile" ]; then \
		make -C  "${NGX_DIR}" clean; \
	fi
	@rm  -rf "${NGX_DIR}" "${NGX_DIST}" 2>1 /dev/null || echo clean # Looks like I really need -f here

kill:
	@if [ -f ${PIDFILE} ]; then \
		kill -2 `cat ${PIDFILE}`; \
	fi;

dirs:
	@mkdir -p ${HOME}/tmp
	@mkdir -p ${HOME}/tmp/body
	@mkdir -p ${HOME}/log

configs: ${TMP_CONF}

${TMP_CONF}:
	cp "${TMP_CONF_TEMPLATE}" "${TMP_CONF}"
	perl -pi -e 's#^(\s*error_log\s+).*#\1"${HOME}/log/error.log" debug;#;' "${TMP_CONF}"
	perl -pi -e 's#^(\s*psgi)\s+.*#\1 "${HOME}/eg/helloworld.psgi";#;'     "${TMP_CONF}"

${NGX_MAKE}: ${NGX_DIR}
	cd ${NGX_DIR} > /dev/null; ./configure \
		--without-http_charset_module \
		--without-http_gzip_module \
		--without-http_ssi_module \
		--without-http_userid_module \
		--without-http_access_module \
		--without-http_auth_basic_module \
		--without-http_autoindex_module \
		--without-http_geo_module \
		--without-http_map_module \
		--without-http_split_clients_module \
		--without-http_referer_module \
		--without-http_rewrite_module \
		--without-http_proxy_module \
		--without-http_fastcgi_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--without-http_memcached_module \
		--without-http_limit_zone_module \
		--without-http_limit_req_module \
		--without-http_empty_gif_module \
		--without-http_browser_module \
		--without-http_upstream_ip_hash_module \
		--conf-path="${TMP_CONF}" \
		--error-log-path="${HOME}/log/error.log" \
		--http-client-body-temp-path="${HOME}/tmp/body" \
		--http-log-path="${HOME}/log/access.log" \
		--lock-path="${HOME}/tmp/nginx.lock" \
		--pid-path="${PIDFILE}" \
		--with-debug \
		--add-module="${HOME}"

${NGX_DIR}: ${NGX_DIST}
	tar xzf ${NGX_DIST}

${NGX_DIST}:
	curl -O http://nginx.org/download/${NGX_DIST}
