NGX_DIR=$1;
NGX_OBJDIR=${NGX_DIR}/objs;
NGX_MAKEFILE=${NGX_OBJDIR}/Makefile
NGX_COVER_MAKEFILE=${NGX_MAKEFILE}.cover

if [ ! -d "$NGX_DIR" ]; then
    echo "No such dir: ${NGX_DIR}";
    exit 255;
fi

if [ ! -f $NGX_MAKEFILE ]; then
    echo "No makefile '${NGX_MAKEFILE}'. Forgot to ./configure ?";
    exit 255;
fi

if ! grep -- '-lgcov' ${NGX_MAKEFILE}; then
    echo "Makefile '${NGX_MAKEFILE}' is not configured with '--with-ld-opt=-lgcov'" ;
    echo "Please reconfigure.";
    exit 255;
fi

if ! which cover; then
    echo "Please install Devel::Cover:";
    echo "    curl -L http://cpanmin.us | perl - Devel::Cover\n";
    exit 255;
fi

cp ${NGX_MAKEFILE} ${NGX_COVER_MAKEFILE};
echo "Setting up makefile ${NGX_COVER_MAKEFILE}"
echo >> ${NGX_COVER_MAKEFILE};
echo "cover:" >> ${NGX_COVER_MAKEFILE};
find src -name \*.c | while read file; do \
    oname=$( basename $file | sed -e 's/.c$$/.o/' );
    absname=$( readlink -f $file );
    echo "	\$(CC) -c \$(CFLAGS) -fprofile-arcs -ftest-coverage \$(ALL_INCS) -o objs/addon/src/$oname $absname" >> ${NGX_MAKEFILE}.cover;
done

find . -name \*.gcov -delete;
find ${NGX_DIR} -name \*.gcna -delete;
rm -r cover_db;

make -C ${NGX_DIR} -f ${NGX_COVER_MAKEFILE} cover || exit $?
make -C ${NGX_DIR} || exit $?

PATH=$NGX_OBJDIR:$PATH prove -mr

find src -name \*.c | while read cfile;
do
    gcno=${NGX_OBJDIR}/addon/$( echo $cfile | sed -e 's/\.c$/.gcno/'  );
    echo "file ${gcno}"
    if [ -f $gcno ]; then
        gcov -o $(dirname $gcno) $gcno;
    fi
done
find . -name \*.gcov -print0 | xargs -0 gcov2perl
cover
rm *.gcov
rm ${NGX_COVER_MAKEFILE}
