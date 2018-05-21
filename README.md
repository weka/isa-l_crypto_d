# D bindings for Intel's [ISA-L_crypto](https://github.com/01org/isa-l_crypto) library

* Using [DStep](https://github.com/jacob-carlborg/dstep) and some manual editing
* Based on ISA-L_crypto v2.21.0

## Generating the bindings
1. Generate include files with
```
make -f Makefile.unx install
```
2. Generate D files with
```
dstep -I. --package=deimos.isal_crypto **/*.h
```
3. Rename and move .d files to conform to package names (e.g `deimos/isal_crypto/package.d`, `deimos/isal_crypto/aes_cbc.d`)
4. Edit `deimos/isal_crypto/package.d` to add the public imports present in `isa-l_crypto.h` and fix the module name
