# Include Windows x86_64 in the v1 platform matrix

NSCB v1 targets macOS 15+ on arm64, Windows 11 on x86_64, and Linux x86_64/arm64 with glibc 2.35+. Windows was added to provide desktop capability parity when NSCB is embedded in Argus ROM Toolkit; Android remains outside the NSCB v1 support matrix and may be qualified separately later. Raising any supported platform minimum is treated as a breaking compatibility change, so these floors remain stable throughout the 1.x release line and may only be raised in a breaking release.
