# Makefile

# utils
RM     = /bin/rm
CP     = /bin/cp -f

# compiler/linker
CC = /usr/bin/gcc

# directories
PROJ_DIR          = 
COMMON_DIR        =

# compiler/linker options
LOCAL_INC     = .
INCLUDE       = -I$(LOCAL_INC)
LIBS          = -lpthread

C_FLAGS = -Wall

OBJS          = main.o dnswldcb.o logging.o config.o util.o network.o llist.o data_dict.o request.o response.o access_list.o fw.o \
                cmd.o
CTL_OBJS      = dnswlctl.o

BIN           = dnswld
CTL_BIN       = dnswlctl
CONFIG_FILE   = dnswld.cfg

# for makedepend
SRCS          = 

DEP_INCLUDE   = $(INCLUDE)


.c.o:
	$(CC) $(C_FLAGS) $(INCLUDE) -c -g $<

all: $(BIN) $(CTL_BIN)

$(BIN) : $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(LIBS)

$(CTL_BIN) : $(CTL_OBJS)
	$(CC) -o $(CTL_BIN) $(CTL_OBJS)

install: $(BIN) $(CTL_BIN)
	@ echo "Installing $(BIN) to /usr/local/sbin ...";
	@ if ! [ -d /usr/local/sbin ]; then \
	 	mkdir -p /usr/local/sbin; \
	fi

	@ cp $(BIN) /usr/local/sbin
	@ chmod 755 /usr/local/sbin/$(BIN)

	@ echo "Installing $(CTL_BIN) to /usr/local/bin ...";
	@ if ! [ -d /usr/local/bin ]; then \
	 	mkdir -p /usr/local/bin; \
	fi

	@ cp $(CTL_BIN) /usr/local/bin
	@ chmod 755 /usr/local/bin/$(CTL_BIN)

	@ echo "Installing sample configuration file to /etc ..."
	@ if [ -f $(CONFIG_FILE) ]; then \
		cp -f $(CONFIG_FILE) /etc; \
	  else \
		echo "Sample configuration file not found. Skipping."; \
	fi

clean:
	$(RM) -f $(BIN) $(OBJS)
	$(RM) -f $(CTL_BIN) $(CTL_OBJS)

