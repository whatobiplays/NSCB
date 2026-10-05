# Ship signed, provenance-rich stable releases

Official NSCB releases publish cryptographic checksums, source/version provenance, helper-license notices, and a machine-readable dependency inventory or SBOM. macOS artifacts are signed and notarized, Windows artifacts are code-signed, Linux artifacts carry release integrity metadata, and v1 exposes one stable product channel rather than background beta or nightly update channels.

Standalone TUI may check GitHub Releases for a newer stable NSCB release at most once per 24 hours and present a non-blocking notice; the normal CLI never performs an unsolicited update check but exposes `nscb update check`. NSCB never downloads or installs its own update, and v1 has no update-install command. Normal update checks ignore prereleases; an explicit development/testing option may query prereleases without changing the helper/provider qualification associated with the currently running NSCB release.
