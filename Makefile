# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone

armsifter: armsifter.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@
