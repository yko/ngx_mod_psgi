NGX_VERSION = 1.0.4
HOME = ${CURDIR}
NGX_DIST = nginx-${NGX_VERSION}.tar.gz
NGX_DIR = ${CURDIR}/nginx-${NGX_VERSION}
NGX_MAKE = ${NGX_DIR}/Makefile
TMP_CONF = ${HOME}/tmp/nginx.conf
TMP_CONF_TEMPLATE = ${HOME}/eg/nginx.conf
PIDFILE = ${HOME}/tmp/nginx.pid
NGX_OBJDIR = ${NGX_DIR}/objs
NGX_TMPROOT = ${HOME}/tmpserverroot
NGX_BIN = ${NGX_OBJDIR}/nginx

default: build

build: ${NGX_MAKE} configs
	@make -C ${NGX_DIR}

test: kill ${NGX_BIN} clean_logs configs
	@PATH=${NGX_DIR}/objs:$$PATH           \
	TEST_NGINX_PORT=3000                   \
	TEST_NGINX_SERVROOT="${NGX_TMPROOT}"   \
		prove -lr ${FLAGS} ${TESTS}

demo: kill clean_logs build configs
	clear
	@${NGX_BIN}
	@echo
	@echo Sending simple request with body: \"Client request body\":
	
	curl http://127.0.0.1:3000/ -d "Client request body" -D -
	@echo
	@echo
	@echo What to do now?
	@echo
	@echo
	@echo You may want to see logs:
	@echo
	@echo     ${HOME}/log/access.log
	@echo     ${HOME}/log/error.log
	@echo
	@echo You also may want to edit psgi app or nginx.conf and run \`make demo\` again:
	@echo
	@echo     ${HOME}/eg/helloworld.psgi
	@echo     ${HOME}/tmp/nginx.conf
	@echo


realclean: clean
	@if [ -f "${NGX_DIR}/Makefile" ]; then \
		make -C  "${NGX_DIR}" clean > /dev/null; \
	fi
	@rm  -rf "${NGX_DIR}" "${NGX_DIST}" 2>&1 || echo -n '' # Looks like I really need -f here
	@rm  -r ${HOME}/tmp 2>/dev/null || echo -n ''
	@if [ -d "${NGX_TMPROOT}" ]; then rm  -r "${NGX_TMPROOT}"; fi
	@rm  -r ${HOME}/log 2>/dev/null || echo -n ''

clean: kill clean_logs
	@rm   -r  ${HOME}/tmp/* 2>/dev/null || echo -n ''
	@if [ -f ${NGX_MAKE} ]; then make -C ${NGX_DIR} clean; fi
	@rm -f ${HOME}/*.gcov
	@if [ -d ${HOME}/cover_db ]; then rm -r ${HOME}/cover_db; fi

clean_logs:
	@rm       ${HOME}/log/* 2>/dev/null || echo -n ''

kill:
	@if [ -f ${PIDFILE} ]; then \
		kill -2 `cat ${PIDFILE}`; \
	fi;

dirs:
	@mkdir -p ${HOME}/tmp
	@mkdir -p ${HOME}/tmp/body
	@mkdir -p ${HOME}/log

${NGX_BIN}:
	@make build

configs: dirs ${TMP_CONF}

${TMP_CONF}:
	cp "${TMP_CONF_TEMPLATE}" "${TMP_CONF}"
	@perl -pi -e 's#^(\s*error_log\s+).*#\1"${HOME}/log/error.log" debug;#;' "${TMP_CONF}"
	@perl -pi -e 's#^(\s*psgi)\s+.*#\1 "${HOME}/eg/helloworld.psgi";#;'     "${TMP_CONF}"

${NGX_MAKE}: ${NGX_DIR}
	@cd ${NGX_DIR}; ./configure \
		${NGX_CONF_OPTS} \
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
	@echo Downloading nginx dist: ${NGX_DIST}
	@curl -O http://nginx.org/download/${NGX_DIST}

cover: dirs
	@if ! grep -s -- '-lgcov' ${NGX_OBJDIR}/Makefile; then       \
		rm -f ${NGX_MAKE};                                       \
		NGX_CONF_OPTS="--with-ld-opt=-lgcov" make ${NGX_MAKE};   \
	fi
	util/ngx_coverage.pl "${NGX_DIR}"
