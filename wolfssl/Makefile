bin = test.exe
LIB_NAME = lib/wolfssl.lib
SRC_PATH = src
WOLFCRYPT_PATH = wolfcrypt/src
OBJDIR=obj
memory_model = -ml
CC = wpp
AR = wlib
CFLAGS = -zq -0 -ot -bt=DOS -w2 $(memory_model) -dHAVE_CONFIG_H -dWOLFSSL_USER_SETTINGS -dBUILDING_WOLFSSL -i. -wcd=14
LD = wlink

# begin mTCP stuff
#tcp_h_dir = ..\..\lib\mTCP\TCPINC\
#tcp_c_dir = ..\..\lib\mTCP\TCPLIB\
#
#tcpobjs = packet.obj arp.obj eth.obj ip.obj tcp.obj tcpsockm.obj udp.obj utils.obj dns.obj timer.obj ipasm.obj trace.obj
#
#tcp_compile_options = -0 $(memory_model) -DCFG_H="tcp.cfg" -oh -ok -ot -s -oa -ei -zp2 -zpw -we -ob -ol+ -oi+
#tcp_compile_options += -i=$(tcp_h_dir)
#
#.cpp : $(tcp_c_dir)
#
#.asm : $(tcp_c_dir)
#
#.asm.obj :
#  wasm -0 $(memory_model) $[*
#
#.cpp.obj :
#  wpp $[* $(tcp_compile_options)
# end mTCP stuff

objects = crl.obj dtls.obj dtls13.obj internal.obj internal2.obj keys.obj ocsp.obj ssl.obj tls.obj tls13.obj wolfio.obj aes.obj arc4.obj asn.obj blake2b.obj blake2s.obj camellia.obj chacha20_poly1305.obj cmac.obj coding.obj cpuid.obj curve25519.obj curve448.obj des3.obj dh.obj dsa.obj ecc.obj ed25519.obj ed448.obj error.obj fe_low_mem.obj fe_operations.obj ge_low_mem.obj ge_operations.obj hash.obj hmac.obj integer.obj kdf.obj logging.obj md2.obj md4.obj md5.obj memory.obj pkcs12.obj pkcs7.obj poly1305.obj pwdbased.obj random.obj rc2.obj ripemd.obj rsa.obj sha.obj sha256.obj sha3.obj sha512.obj signature.obj sp_c32.obj sp_c64.obj sp_int.obj sp_x86_64.obj srp.obj tfm.obj wc_encrypt.obj wc_pkcs11.obj wc_port.obj dos_port.obj wolfevent.obj wolfmath.obj 

$(bin): test.obj $(LIB_NAME) 
    $(LD) system dos name $@ file { test.obj $(LIB_NAME) }

$(LIB_NAME): $(objects)
    $(AR) -q $@ $(objects)

test.obj: test.c
	 $(CC) -fo=$@ $(CFLAGS) -i.. $<

crl.obj: $(SRC_PATH)/crl.c
	 $(CC) -fo=$@ $(CFLAGS) $<

dtls.obj: $(SRC_PATH)/dtls.c
	 $(CC) -fo=$@ $(CFLAGS) $<

dtls13.obj: $(SRC_PATH)/dtls13.c
	 $(CC) -fo=$@ $(CFLAGS) $<

internal.obj: $(SRC_PATH)/internal.c
	 $(CC) -fo=$@ $(CFLAGS) $<

internal2.obj: $(SRC_PATH)/internal2.c
	 $(CC) -fo=$@ $(CFLAGS) $<

keys.obj: $(SRC_PATH)/keys.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ocsp.obj: $(SRC_PATH)/ocsp.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ssl.obj: $(SRC_PATH)/ssl.c
	 $(CC) -fo=$@ $(CFLAGS) $<

tls.obj: $(SRC_PATH)/tls.c
	 $(CC) -fo=$@ $(CFLAGS) $<

tls13.obj: $(SRC_PATH)/tls13.c
	 $(CC) -fo=$@ $(CFLAGS) $<

wolfio.obj: $(SRC_PATH)/wolfio.c
	 $(CC) -fo=$@ $(CFLAGS) $<

aes.obj: $(WOLFCRYPT_PATH)/aes.c
	 $(CC) -fo=$@ $(CFLAGS) $<

arc4.obj: $(WOLFCRYPT_PATH)/arc4.c
	 $(CC) -fo=$@ $(CFLAGS) $<
	 
asn.obj: $(WOLFCRYPT_PATH)/asn.c
	 $(CC) -fo=$@ $(CFLAGS) $<
	 
blake2b.obj: $(WOLFCRYPT_PATH)/blake2b.c
	 $(CC) -fo=$@ $(CFLAGS) $<

blake2s.obj: $(WOLFCRYPT_PATH)/blake2s.c
	 $(CC) -fo=$@ $(CFLAGS) $<

camellia.obj: $(WOLFCRYPT_PATH)/camellia.c
	 $(CC) -fo=$@ $(CFLAGS) $<

chacha.obj: $(WOLFCRYPT_PATH)/chacha.c
	 $(CC) -fo=$@ $(CFLAGS) $<

chacha20_poly1305.obj: $(WOLFCRYPT_PATH)/chacha20_poly1305.c
	 $(CC) -fo=$@ $(CFLAGS) $<

cmac.obj: $(WOLFCRYPT_PATH)/cmac.c
	 $(CC) -fo=$@ $(CFLAGS) $<

coding.obj: $(WOLFCRYPT_PATH)/coding.c
	 $(CC) -fo=$@ $(CFLAGS) $<

cpuid.obj: $(WOLFCRYPT_PATH)/cpuid.c
	 $(CC) -fo=$@ $(CFLAGS) $<

curve25519.obj: $(WOLFCRYPT_PATH)/curve25519.c
	 $(CC) -fo=$@ $(CFLAGS) $<

curve448.obj: $(WOLFCRYPT_PATH)/curve448.c
	 $(CC) -fo=$@ $(CFLAGS) $<

des3.obj: $(WOLFCRYPT_PATH)/des3.c
	 $(CC) -fo=$@ $(CFLAGS) $<

dh.obj: $(WOLFCRYPT_PATH)/dh.c
	 $(CC) -fo=$@ $(CFLAGS) $<

dsa.obj: $(WOLFCRYPT_PATH)/dsa.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ecc.obj: $(WOLFCRYPT_PATH)/ecc.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ed25519.obj: $(WOLFCRYPT_PATH)/ed25519.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ed448.obj: $(WOLFCRYPT_PATH)/ed448.c
	 $(CC) -fo=$@ $(CFLAGS) $<

error.obj: $(WOLFCRYPT_PATH)/error.c
	 $(CC) -fo=$@ $(CFLAGS) $<

fe_low_mem.obj: $(WOLFCRYPT_PATH)/fe_low_mem.c
	 $(CC) -fo=$@ $(CFLAGS) $<

fe_operations.obj: $(WOLFCRYPT_PATH)/fe_operations.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ge_low_mem.obj: $(WOLFCRYPT_PATH)/ge_low_mem.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ge_operations.obj: $(WOLFCRYPT_PATH)/ge_operations.c
	 $(CC) -fo=$@ $(CFLAGS) $<

hash.obj: $(WOLFCRYPT_PATH)/hash.c
	 $(CC) -fo=$@ $(CFLAGS) $<

hmac.obj: $(WOLFCRYPT_PATH)/hmac.c
	 $(CC) -fo=$@ $(CFLAGS) $<

integer.obj: $(WOLFCRYPT_PATH)/integer.c
	 $(CC) -fo=$@ $(CFLAGS) $<

kdf.obj: $(WOLFCRYPT_PATH)/kdf.c
	 $(CC) -fo=$@ $(CFLAGS) $<

logging.obj: $(WOLFCRYPT_PATH)/logging.c
	 $(CC) -fo=$@ $(CFLAGS) $<

md2.obj: $(WOLFCRYPT_PATH)/md2.c
	 $(CC) -fo=$@ $(CFLAGS) $<

md4.obj: $(WOLFCRYPT_PATH)/md4.c
	 $(CC) -fo=$@ $(CFLAGS) $<

md5.obj: $(WOLFCRYPT_PATH)/md5.c
	 $(CC) -fo=$@ $(CFLAGS) $<

memory.obj: $(WOLFCRYPT_PATH)/memory.c
	 $(CC) -fo=$@ $(CFLAGS) $<

pkcs12.obj: $(WOLFCRYPT_PATH)/pkcs12.c
	 $(CC) -fo=$@ $(CFLAGS) $<

pkcs7.obj: $(WOLFCRYPT_PATH)/pkcs7.c
	 $(CC) -fo=$@ $(CFLAGS) $<

poly1305.obj: $(WOLFCRYPT_PATH)/poly1305.c
	 $(CC) -fo=$@ $(CFLAGS) $<

pwdbased.obj: $(WOLFCRYPT_PATH)/pwdbased.c
	 $(CC) -fo=$@ $(CFLAGS) $<

random.obj: $(WOLFCRYPT_PATH)/random.c
	 $(CC) -fo=$@ $(CFLAGS) $<

rc2.obj: $(WOLFCRYPT_PATH)/rc2.c
	 $(CC) -fo=$@ $(CFLAGS) $<

ripemd.obj: $(WOLFCRYPT_PATH)/ripemd.c
	 $(CC) -fo=$@ $(CFLAGS) $<

rsa.obj: $(WOLFCRYPT_PATH)/rsa.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sha.obj: $(WOLFCRYPT_PATH)/sha.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sha256.obj: $(WOLFCRYPT_PATH)/sha256.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sha3.obj: $(WOLFCRYPT_PATH)/sha3.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sha512.obj: $(WOLFCRYPT_PATH)/sha512.c
	 $(CC) -fo=$@ $(CFLAGS) $<

signature.obj: $(WOLFCRYPT_PATH)/signature.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sp_c32.obj: $(WOLFCRYPT_PATH)/sp_c32.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sp_c64.obj: $(WOLFCRYPT_PATH)/sp_c64.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sp_int.obj: $(WOLFCRYPT_PATH)/sp_int.c
	 $(CC) -fo=$@ $(CFLAGS) $<

sp_x86_64.obj: $(WOLFCRYPT_PATH)/sp_x86_64.c
	 $(CC) -fo=$@ $(CFLAGS) $<

srp.obj: $(WOLFCRYPT_PATH)/srp.c
	 $(CC) -fo=$@ $(CFLAGS) $<

tfm.obj: $(WOLFCRYPT_PATH)/tfm.c
	 $(CC) -fo=$@ $(CFLAGS) $<

wc_encrypt.obj: $(WOLFCRYPT_PATH)/wc_encrypt.c
	 $(CC) -fo=$@ $(CFLAGS) $<

wc_pkcs11.obj: $(WOLFCRYPT_PATH)/wc_pkcs11.c
	 $(CC) -fo=$@ $(CFLAGS) $<

wc_port.obj: $(WOLFCRYPT_PATH)/wc_port.c
	 $(CC) -fo=$@ $(CFLAGS) $<

dos_port.obj: $(WOLFCRYPT_PATH)/dos_port.c
	 $(CC) -fo=$@ $(CFLAGS) $<

wolfevent.obj: $(WOLFCRYPT_PATH)/wolfevent.c
	 $(CC) -fo=$@ $(CFLAGS) $<

wolfmath.obj: $(WOLFCRYPT_PATH)/wolfmath.c
	 $(CC) -fo=$@ $(CFLAGS) $<


clean: .symbolic
    del *.obj
    del $(bin)