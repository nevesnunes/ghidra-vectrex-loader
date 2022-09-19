# Ghidra Vectex Loader

Loads game ROMs for the GCE Vectrex console. Adds memory map and labels for BIOS functions and I/O ports.

## References

- [vectrexmuseum\.com \- CODERS PAGES \- ROM Reference](http://vectrexmuseum.com/share/coder/html/appendixa.htm#Reference)
- [vectrexmuseum\.com \- CODERS PAGES \- BIOS RAM locations](http://vectrexmuseum.com/share/coder/html/appendixb.htm)

## Usage

```sh
GHIDRA_INSTALL_DIR=
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR buildExtension
mv dist/ghidra_*.zip "$GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
```

## TODO

* String detection
* Optionally load BIOS rom
* [6809 issue] Fix decompilation sometimes failing
