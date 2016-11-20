WRUN_SOURCES = wrun.c xalloc.c err.c str.c common.c
WCMD_SOURCES = wcmd.c xalloc.c err.c

HEADERS = common.h err.h nvec.h str.h xalloc.h

DEFINES = -D_XOPEN_SOURCE=700 -D_BSD_SOURCE

.PHONY: all
all: wrun wcmd wstart

wrun: $(WRUN_SOURCES) $(HEADERS)
	gcc $(DEFINES) -O2 -Wall -Wextra -pthread -std=c11 -o $@ -flto $(WRUN_SOURCES)

wcmd: $(WCMD_SOURCES) $(HEADERS)
	gcc $(DEFINES) -O2 -Wall -Wextra          -std=c11 -o $@ -flto $(WCMD_SOURCES)

wstart: wcmd
	ln -f wcmd wstart

.PHONY: install
install: wrun wcmd wstart
	install -s -t /usr/local/bin/ wrun
	install -s -t /usr/local/bin/ wcmd
	cd /usr/local/bin && ln -f wcmd wstart

.PHONY: cppcheck
cppcheck:
	cppcheck -j4 --enable=all *.c

.PHONY: clean
clean:
	rm -rf wrun wcmd wstart
