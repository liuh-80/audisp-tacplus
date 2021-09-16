#disable some warning because UT need test functions not in header file.
CFLAGS = -Wno-parentheses -Wno-format-security -Wno-implicit-function-declaration -c
IFLAGS = -I.. -I../include -I../lib
MFLAG = -DDEBUG -DBASH_PLUGIN_UT

all:
	gcc user_secret_test.c $(IFLAGS) $(CFLAGS) -o user_secret_test.o
	gcc mock_helper.c $(IFLAGS) $(CFLAGS) -o mock_helper.o
	gcc ../user_secret.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o user_secret.o
	gcc  user_secret_test.o  mock_helper.o user_secret.o -o user_secret_test  -lc -lcunit 

test:
	# run unit test, if UT failed, build will break
	./user_secret_test

clean:
	rm *.o
	rm user_secret_test
