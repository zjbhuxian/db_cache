# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=db_cache.so
LIBS=-lsqlite3 -lpthread
include ../../Makefile.modules
