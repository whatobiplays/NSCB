# Expose NSCB as an embeddable Rust capability

NSCB is a standalone product and an embeddable Switch-content capability. Rust hosts such as Argus ROM Toolkit integrate the NSCB library directly rather than invoking the CLI or crossing a C/Flutter bridge; NSCB exposes its full supported capability set while each host owns which capabilities it presents, and NSCB contains no Argus-specific product policy.
