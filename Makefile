
BASE=$(shell pwd)
OSNAME=$(shell uname)

CFGOPTS += --with-crypto
CFGOPTS += --enable-magic

ifeq ($(OSNAME),Darwin)
CFLAGS  += -I/usr/local/include/node
CFLAGS  += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
endif

YARA=3.6.0

libyara: yara

yara:
	-rm -rf $(BASE)/deps/yara-$(YARA)
	cd $(BASE)/deps && tar -xzvf yara-$(YARA).tar.gz
	cd $(BASE)/deps/yara-$(YARA) && ./bootstrap.sh
	cd $(BASE)/deps/yara-$(YARA) && \
			CFLAGS="$(CFLAGS)" \
			LDFLAGS="$(LDFLAGS)" \
			./configure \
					$(CFGOPTS) \
					--enable-static \
					--disable-shared \
					--with-pic \
					--prefix=$(BASE)/deps/yara-$(YARA)/build
	cd $(BASE)/deps/yara-$(YARA) && make
	cd $(BASE)/deps/yara-$(YARA) && make install
