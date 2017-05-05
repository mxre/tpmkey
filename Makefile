LIBRARIES = -lkeyutils -ltspi -ltpm_unseal -ludev
INCLUDES =

# source files
SOURCES = \
	src/tpmkey.c

# set required C flags
CFLAGS += -std=c11 -D_POSIX_C_SOURCE=200809L -DUDEV

# executable name
BINARY = tpmkey

# don't print build commands
.SILENT:
.PHONY: all clean dist debug dist

OBJECTS = $(patsubst src/%.c,obj/%.o,$(SOURCES))

all: $(OBJECTS:.o=.d) $(BINARY)

# build for release
dist: CFLAGS += -O3 -g0 -Wall -fPIC -DNDEBUG -D_FORTIFY_SOURCE=2 -fstack-protector-strong --param=ssp-buffer-size=4
dist: LDFLAGS += -pie -Wl,-S,-O1,--sort-common,-z,relro,-z,now
dist: all

# build for debug
debug: CFLAGS += -O0 -g3 -Wall -Wextra -DDEBUG
debug: LDFLAGS +=
debug: all

$(BINARY): $(OBJECTS)
	@echo -e "\x1b[33mCCLD\x1b[0m $@"
	$(CC) $(LDFLAGS) $^ $(LIBRARIES) -o $@

obj/%.d: src/%.c
	@test -d obj || mkdir obj
	@#echo -e "\x1b[33mDEP\x1b[0m  $<"
	$(CC) $(CFLAGS) $(INCLUDES) $< -MM -MF $@

obj/%.o: src/%.c
	@test -d obj || mkdir obj
	@echo -e "\x1b[32mCC\x1b[0m   $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@echo -e "\x1b[31mRM\x1b[0m   $(OBJECTS) $(BINARY)"
	$(RM) $(OBJECTS) $(BINARY) $(OBJECTS:.o=.d)

install: dist
	@echo -e "\x1b[34mINST\x1b[0m /usr/lib/initcpio/tpm/tcsd.conf"
	install -m644 data/tcsd.conf "/usr/lib/initcpio/tpm"
	@echo -e "\x1b[34mINST\x1b[0m /usr/lib/initcpio/install/sd-tpm"
	install -m644 data/sd-tpm "/usr/lib/initcpio/install"
	#@echo -e "\x1b[34mINST\x1b[0m /usr/lib/systemd/system/tcsd.service"
	#install -m644 data/tcsd.service "/usr/lib/systemd/system"
	#@echo -e "\x1b[34mINST\x1b[0m /usr/lib/systemd/system/tcsd.socket"
	#install -m644 data/tcsd.socket "/usr/lib/systemd/system"
	@echo -e "\x1b[34mINST\x1b[0m /usr/lib/systemd/system/tpmkey.service"
	install -m644 data/tpmkey.service "/usr/lib/systemd/system"
	@echo -e "\x1b[34mINST\x1b[0m /usr/bin/tpmkey"
	install -m755 tpmkey "/usr/bin"

-include $(OBJECTS:.o=.d)
