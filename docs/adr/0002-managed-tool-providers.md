# Compose qualified external tools behind managed providers

NSCB may delegate specialized format, cryptographic, compression, or device mechanics to mature external executables instead of reimplementing every capability. Those tools are hidden behind NSCB-owned typed capability contracts, pinned to exact qualified versions, downloaded and verified through an NSCB-managed tool manifest, and validated as part of development and release qualification; runtime discovery of arbitrary tools or silent provider substitution is not part of the supported model.
