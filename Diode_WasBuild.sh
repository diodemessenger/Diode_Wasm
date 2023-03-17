#!/bin/bash

EXPORTED_FUNCS="'__diode_mceliece460896f_Keygen', '__diode_mceliece460896f_b64PublicKeySizeInChars', '__diode_mceliece460896f_b64PrivateKeySizeInChars', '__diode_VerifySig_wED25519PublicBase64Key', '__diode_SignString_wED25519PrivateBase64Key', '__diode_ED25519_CopyKeys_Base64Str', '__diode_ED25519_Base64PublicKeySize', '__diode_ED25519_Base64PrivateKeySize', '__diode_ED25519_Keygen', '__diode_Init', '__diode_Close', '_main', '_free', '_crypto_kem_mceliece460896f_ref_enc', '_crypto_kem_mceliece460896f_ref_dec', '_crypto_kem_mceliece460896f_ref_keypair', '_DEBUG_print'"

#Flags
DEPS_Y="false"
OPTIMIZE=""
MAKE_TRACE=""
MAKE_CLEAN="false"
while getopts 'dxtc' flag; do
  case "${flag}" in
    d) DEPS_Y="true" ;;
    x) OPTIMIZE="-O3" ;;
    t) MAKE_TRACE="--trace" ;;
    c) MAKE_CLEAN="true" ;;
  esac
done

MAIN_WD=$(pwd)
export CC=emcc
export AR=emar
export RANLIB=emranlib
export AS=wasm-as
export LD=wasm-ld-14
export CXX=em++
export SRC_DIRS=""
export INC_DIRS=""
export LFLAGS=""
export CFLAGS=""

mkdir -p dependacies
mkdir -p dependacies/lib
mkdir -p dependacies/include
mkdir -p dependacies/include/openssl
mkdir -p dependacies/share
mkdir -p dependacies/doc
mkdir -p src

#Source files
if [ ! -f "$MAIN_WD/src/DEBUG_mc_print.c"  ]
then
	read -r -d '' MCELIECE_DEBUG_PRINT_SOURCE <<- EOM
	#include <stdio.h>\n

	void    DEBUG_print(unsigned char *A, unsigned long long L)
	{
		unsigned long long i;

		for ( i=0; i<L; i++ )
			fprintf(stdout, "%02X", A[i]);

		if ( L == 0 )
			fprintf(stdout, "00");
	}
	EOM
	touch ./src/DEBUG_mc_print.c
	echo -e $MCELIECE_DEBUG_PRINT_SOURCE > ./src/DEBUG_mc_print.c
fi

#Dependacies

if [ "$DEPS_Y" = "true" ] ; then
cd dependacies
	__WD=$(pwd)

	#Openssl
	git clone --depth=1 https://github.com/openssl/openssl.git
	cd openssl

	# no-autoerrinit removes the error strings, smaller static link lib but worst for debugging
	# no-deprecated no-autoerrinit no-module
	./Configure --prefix=$__WD --release linux-generic32 no-autoerrinit no-module no-afalgeng no-threads no-shared no-tests -fPIC -DOPENSSL_PIC
	emmake make clean -j4
	emmake make ordinals -j4
	emmake make libcrypto.a -j4
	emranlib libcrypto.a
	emmake make libssl.a -j4
	emranlib libssl.a
	make test -j4
	make install -j4
	cd ..


	#XKCP (new keccak lib)
	git clone --depth=1 https://github.com/XKCP/XKCP
	cd XKCP
	emmake make generic32/libXKCP.a -j4
	emranlib ./bin/generic32/libXKCP.a
	cp ./bin/generic32/libXKCP.a $__WD/lib/libkeccak.a
	cp -r ./bin/generic32/libXKCP.a.headers $__WD/include/libkeccak.a.headers
	cd ..

	export SRC_DIRS=""
	export INC_DIRS=""
	export LFLAGS=""
	export CFLAGS=""


	#GF2X
	#git clone --depth=1 https://gitlab.inria.fr/gf2x/gf2x.git
	#cd gf2x
	#autoreconf -fvi
	#emconfigure ./configure --disable-shared --host=x86-windows CFLAGS="$OPTIMIZE" ABI=32 --prefix=$__WD --exec-prefix=$__WD --disable-assembly
	#emmake make -j4
	#emranlib ./.libs/libgf2x.a
	#emmake make install -j4
	#cd ..


	#GMP
	#if [ ! -f "gmp-6.2.1.tar.lz"  ]
	#then
	#	wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.lz
	#fi

	#if [ ! -d "gmp-6.2.1" ]
	#then
	#	tar --lzip -xvf gmp-6.2.1.tar.lz
	#fi
	#cd gmp-6.2.1 
	#./configure --prefix=$__WD --exec-prefix=$__WD --disable-shared --disable-assembly --host=x86-windows
	#emmake make -j4
	#emranlib ./.libs/libgmp.a
	#emmake make install -j4
	#cd ..

	
	#NTL
	#if [ ! -f "ntl-11.5.1.tar.gz"  ]
        #then
	#	wget https://libntl.org/ntl-11.5.1.tar.gz
        #fi

        #if [ ! -d "ntl-11.5.1" ]
        #then
        #        tar -xvf ntl-11.5.1.tar.gz
        #fi
	#cp ../DoConfig ./ntl/src
	#cd ntl/src
	#./configure DEF_PREFIX=$__WD NTL_GF2X_LIB=on "CXXAUTOFLAGS=-std=c++11 -pthread -lgf2x -L/home/rod/Diode/dependacies/lib -I/home/rod/Diode/dependacies/include -I../include" "CXXFLAGS=-g -O2" NATIVE=off CXX=em++ SHARED=off TUNE=generic AR=emar RANLIB=emranlib
	
	#cd ../../


cd ..
fi


#Downloading McEliece Algorithm

if [ ! -f "mceliece-Round4.tar.gz"  ]
then
	wget https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/submissions/mceliece-Round4.tar.gz
fi

if [ ! -d "mceliece-20221023" ]
then
	tar -xvf mceliece-Round4.tar.gz
fi


#Mceliece Algorithm
export MCELIECE_PWD=$(pwd)/mceliece-20221023/Optimized_Implementation/kem/mceliece460896f

export TARGET_NAME=Classic_McEliece
export TARGET_DIR=$MCELIECE_PWD

export SRC_DIRS="$MAIN_WD/src $MCELIECE_PWD $MCELIECE_PWD/nist $MCELIECE_PWD/subroutines "

export INC_DIRS="$MAIN_WD/dependacies/include $MCELIECE_PWD $MCELIECE_PWD/nist $MCELIECE_PWD/subroutines $MAIN_WD/include"


export LFLAGS="-s LLD_REPORT_UNDEFINED -L$MAIN_WD/dependacies/lib -s \"EXPORTED_RUNTIME_METHODS=['ccall', 'cwrap']\" -s \"EXPORTED_FUNCTIONS=[$EXPORTED_FUNCS]\" -lssl -lkeccak -lcrypto -ldl"

KATNUM_I=$(cat $MCELIECE_PWD/KATNUM)

export CFLAGS="$OPTIMIZE -march=native -mtune=native -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-sign-compare -DKAT -DKATNUM=$KATNUM_I \"-DCRYPTO_NAMESPACE(x)=x\" \"-D_CRYPTO_NAMESPACE(x)=_##x\""

if [ "$MAKE_CLEAN" = "true" ] ; then
	emmake make -j4 -C$MCELIECE_PWD -f$MAIN_WD/Makefile clean $MAKE_TRACE
else
	emmake make -j4 -C$MCELIECE_PWD -f$MAIN_WD/Makefile $MAKE_TRACE
fi

cp $MCELIECE_PWD/*tar.gz ./

export SRC_DIRS=""
export INC_DIRS=""
export LFLAGS=""
export CFLAGS=""



# Download HQC Algorithm
#if [ ! -f "$MAIN_WD/HQC/HQC-Round4.zip"  ]
#then
#	cd HQC
#        wget https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/submissions/HQC-Round4.zip
#fi

#if [ ! -d "$MAIN_WD/HQC/Optimized_Implementation" ]
#then
#        cd HQC
#	unzip HQC-Round4.zip
#fi

#cd $MAIN_WD

# HQC Algorithm
#export HQC_PWD="$(pwd)/HQC/Optimized_Implementation/hqc-256"

#export TARGET_NAME="HQC"
#export TARGET_DIR="$HQC_PWD"

#export SRC_DIRS="$HQC_PWD/src $HQC_PWD/lib/fips202"
#export INC_DIRS="$HQC_PWD/src $HQC_PWD/lib/fips202"

#export LFLAGS=""

#export CFLAGS="-msimd128 -O3 -std=c99 -funroll-all-loops -flto -mavx -mavx2 -mbmi -mpclmul -pedantic -Wall -Wextra"

#if [ "$MAKE_CLEAN" = "true" ] ; then
#        emmake make -j4 -C$HQC_PWD -f$MAIN_WD/Makefile clean $MAKE_TRACE
#else
#        emmake make -j4 -C$HQC_PWD -f$MAIN_WD/Makefile $MAKE_TRACE
#fi

#cp $HQC_PWD/*tar.gz ./

#Download BYKE Algorithm
#if [ ! -f "$MAIN_WD/BIKE/BIKE-Round4.zip"  ]
#then
#	cd BIKE
#        wget https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/submissions/BIKE-Round4.zip
#fi

#if [ ! -d "$MAIN_WD/BIKE/Reference_Implementation" ]
#then
#	cd BIKE
#        unzip HQC-Round4.zip
#fi

#cd $MAIN_WD

#BYKE Algorithm

