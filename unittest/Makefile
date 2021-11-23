#disable some warning because UT need test functions not in header file.
CFLAGS = -Wno-parentheses -Wno-format-security -Wno-implicit-function-declaration -c
IFLAGS = -I.. -I../include -I../lib -include mock.h
MFLAG = -DDEBUG -DUNIT_TEST 

all:
	gcc password_test.c $(IFLAGS) $(CFLAGS) -o password_test.o
	gcc mock_helper.c $(IFLAGS) $(CFLAGS) -o mock_helper.o
	gcc ../password.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o password.o
	gcc ../regex_helper.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o regex_helper.o
	gcc ../trace.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o trace.o
	gcc ../sudoers_helper.c   $(IFLAGS) $(CFLAGS) $(MFLAG) -o sudoers_helper.o
	gcc  password_test.o  mock_helper.o password.o regex_helper.o trace.o sudoers_helper.o -o password_test  -lc -lcunit 

test:
	# run unit test, if UT failed, build will break
	./password_test

clean:
	rm *.o
	rm password_test
