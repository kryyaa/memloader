# memloader

memloader is a manual PE loader that loads and runs a Windows executable directly from embedded bytes in memory, without writing any files to disk.

---

## Features

- Loads executables from embedded byte arrays without dropping files to disk  
- Parses and maps PE headers and sections correctly  
- Applies relocations if loaded at a different base address  
- Dynamically resolves imports using LoadLibrary and GetProcAddress  
- Runs the executable entry point in a separate thread and waits for it  
- Frees allocated memory after execution  

---

## Why Use memloader?

- **Stealth:** No disk footprint minimizes detection  
- **Flexibility:** Embed any PE executable as raw bytes  
- **Control:** Full manual loading for customization  
- **Simplicity:** Easy to integrate with minimal dependencies  

---

## How It Works

- **bytes.hpp:** Store your executable as a static `unsigned char[]` array and provide its size  
- **load.hpp:** Implements the manual loader that:  
  - Parses PE headers from the embedded bytes  
  - Allocates memory with proper permissions  
  - Copies headers and sections into memory  
  - Applies base relocations if needed  
  - Resolves imports dynamically  
  - Runs the PE entry point on a new thread and waits for it  

---

## Usage

1. Define your EXE bytes in `bytes.cpp` as:  
   `static unsigned char EXEbytes[] = { ... };`  
   and define `size_t EXEbytesSize = sizeof(EXEbytes);`  
2. Declare these in `bytes.hpp` as:  
   `extern unsigned char EXEbytes[];`  
   `extern size_t EXEbytesSize;`  
3. Include `load.hpp` in your project and call `loadbytes()` to load and execute the embedded EXE bytes from memory.

---

## Note

The currently embedded bytes are a simple `MessageBox` executable used for demonstration purposes.  
You can replace it with any valid PE (Portable Executable) file exported as a byte array using a hex editor (like [HxD](https://mh-nexus.de/en/hxd/)).  

Make sure the PE you're embedding is compatible with the loader (e.g., 64-bit vs 32-bit, no external dependencies unless resolved manually).

---
