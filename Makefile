IWINFO_SOVERSION   = $(if $(SOVERSION),$(SOVERSION),0)

IWINFO_BACKENDS    = $(BACKENDS)
IWINFO_CFLAGS      = $(CFLAGS) -Wall -std=gnu99 -fstrict-aliasing -Iinclude
IWINFO_LDFLAGS     =

IWINFO_LIB         = libiwinfo-mt.so
IWINFO_LIB_LDFLAGS = $(LDFLAGS) -shared -Wl,-soname -Wl,$(IWINFO_LIB).$(IWINFO_SOVERSION)
IWINFO_LIB_OBJ     = iwinfo_utils-mt.o iwinfo_lib-mt.o


IWINFO_CLI         = iwinfo-mt
IWINFO_CLI_LDFLAGS = $(LDFLAGS) -L. -liwinfo-mt
IWINFO_CLI_OBJ     = iwinfo_cli-mt.o



ifneq ($(filter nl80211,$(IWINFO_BACKENDS)),)
	IWINFO_CFLAGS      += -DUSE_NL80211
	IWINFO_CLI_LDFLAGS += -lnl-tiny
	IWINFO_LIB_LDFLAGS += -lnl-tiny
	IWINFO_LIB_OBJ     += iwinfo_nl80211-mt.o
endif


compile: clean $(IWINFO_LIB) $(IWINFO_CLI)

%.o: %.c
	$(CC) $(IWINFO_CFLAGS) $(FPIC) -c -o $@ $<

$(IWINFO_LIB): $(IWINFO_LIB_OBJ)
	$(CC) $(IWINFO_LDFLAGS) $(IWINFO_LIB_LDFLAGS) -o $(IWINFO_LIB).$(IWINFO_SOVERSION) $(IWINFO_LIB_OBJ) && \
	ln -sf $(IWINFO_LIB).$(IWINFO_SOVERSION) $(IWINFO_LIB)

$(IWINFO_CLI): $(IWINFO_CLI_OBJ)
	$(CC) $(IWINFO_LDFLAGS) $(IWINFO_CLI_LDFLAGS) -o $(IWINFO_CLI) $(IWINFO_CLI_OBJ)

clean:
	rm -f *.o $(IWINFO_LIB) $(IWINFO_CLI)
