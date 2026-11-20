SUMMARY = "Acme gateway agent (proprietary)"
LICENSE = "CLOSED"
DEPENDS = "readline openssl"
SRC_URI = "file://agent.c file://Makefile"
do_compile() { oe_runmake LDLIBS="-lreadline -lssl -lcrypto" }
