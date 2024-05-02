set PATH=c:\watcom\binnt;%PATH%
set INCLUDE=c:\watcom\h
set WATCOM=c:\watcom
set EDPATH=c:\watcom\eddat
set WIPFC=c:\watcom\wipfc
set LIBDOS=c:\watcom\lib286\dos;c:\watcom\lib286

cd ..
wmake.exe -f Makefile clean
wmake.exe -f Makefile
