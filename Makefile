LIBRARIES = -lkeyutils -ludev -lgcrypt
INCLUDES = -Ilibtpm

# source files
SOURCES = \
	src/tpmkey.c

LIBTPM = \
    libtpm/delegation.c libtpm/eviction.c libtpm/hmac.c libtpm/keys.c libtpm/keyswap.c libtpm/oiaposap.c \
	libtpm/pcrs.c libtpm/rng.c libtpm/serialize.c libtpm/session.c libtpm/seal.c libtpm/miscfunc.c \
	libtpm/transport.c libtpm/tpmutil.c libtpm/tpmutil_dev.c

# set required C flags
CFLAGS += -mrdrnd -std=gnu11 -D_GNU_SOURCE=1 -DTPM_POSIX=1 -DTPM_V12=1 -DTPM_USE_TAG_IN_STRUCTURE=1 -DTPM_USE_CHARDEV=1 -DTPM_NV_DISK=1 -DTPM_AES=1

# executable name
BINARY = tpmkey

# don't print build commands
.SILENT:
.PHONY: all clean dist debug dist

OBJECTS = $(patsubst src/%.c,obj/%.o,$(SOURCES))
LIBTPM_O = $(patsubst libtpm/%.c,obj/%.o,$(LIBTPM))

all: $(OBJECTS:.o=.d) $(LIBTPM_O:.o=.d) $(BINARY)

# build for release
dist: CFLAGS += -O3 -g0 -Wall -fPIC -DNDEBUG -D_FORTIFY_SOURCE=2 -fstack-protector-strong --param=ssp-buffer-size=4
dist: LDFLAGS += -pie -Wl,-s,-O1,--sort-common,-z,relro,-z,now
dist: all

# build for debug
debug: CFLAGS += -O0 -g3 -Wall -Wextra
debug: LDFLAGS +=
debug: all

$(BINARY): $(OBJECTS) obj/libtpm.a
	@echo -e "\x1b[33mCCLD\x1b[0m $<"
	$(CC) $(LDFLAGS) $^ $(LIBRARIES) -o $@

obj/libtpm.a: $(LIBTPM_O)
	@echo -e "\x1b[33mAR\x1b[0m   $@"
	ar rcs $@ $^

obj/%.d: libtpm/%.c
	@test -d obj || mkdir obj
	@echo -e "\x1b[33mDEP\x1b[0m  $<"
	$(CC) $(CFLAGS) $(INCLUDES) $< -MM -MF $@

obj/%.o: libtpm/%.c
	@test -d obj || mkdir obj
	@echo -e "\x1b[32mCC\x1b[0m   $<"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

obj/%.d: src/%.c
	@test -d obj || mkdir obj
	@echo -e "\x1b[33mDEP\x1b[0m  $<"
	$(CC) $(CFLAGS) $(INCLUDES) $< -MM -MF $@

obj/%.o: src/%.c
	@test -d obj || mkdir obj
	@echo -e "\x1b[32mCC\x1b[0m   $<"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@echo -e "\x1b[31mRM\x1b[0m   $(OBJECTS) $(BINARY)"
	$(RM) $(OBJECTS) $(BINARY) $(OBJECTS:.o=.d)
	@echo -e "\x1b[31mRM\x1b[0m   $(LIBTPM_O)"
	$(RM) $(LIBTPM_O) $(LIBTPM_O:.o=.d)

install: dist
	@echo -e "\x1b[34mINST\x1b[0m /usr/lib/initcpio/install/sd-tpm"
	install -m644 data/sd-tpm "/usr/lib/initcpio/install"
	@echo -e "\x1b[34mINST\x1b[0m /usr/lib/systemd/system/tpmkey.service"
	install -m644 data/tpmkey.service "/usr/lib/systemd/system"
	@echo -e "\x1b[34mINST\x1b[0m /usr/lib/tpmkey"
	install -m755 tpmkey "/usr/lib"

-include $(OBJECTS:.o=.d) $(LIBTPM_O:.o=.d)
