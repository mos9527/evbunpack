El Psy Kongroo.
^ This line is used to test if the unpacked app can still read files properly.

Notes on the provided test files:
---
PackerTestApp.exe
    - The original executable. The source is available at ../example/PackerTestApp
    - TLS is used. And checked when run.
    - Exception Directory is used. And checked when run.
    - Overlay is used. And checked when run.
PackerTestApp_packed_20240522.exe
    - Packed with EVB 10.70
PackerTestApp_packed_20170713.exe
    - Packed with EVB 7.80

The app will fail with error codes. Here are their definitions.
---
EXIT_OK(0)
    - No issues have been detected
EXIT_INVALID_FS(1)
    - *This* file cannot be read properly.
EXIT_INVALID_TLS(2)
    - Thread Local Storage is botched. RIP.
EXIT_INVALID_OVERLAY(3)
    - Overlay data is incorrect.
