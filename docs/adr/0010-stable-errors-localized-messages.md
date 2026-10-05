# Separate stable error semantics from localized presentation

NSCB exposes stable typed error categories/codes and structured context across its CLI, Flutter bridge, and Rust embedding facade, while human-facing error text is localized presentation owned outside those stable semantics. User-visible messages never expose implementation details, code references, raw helper output, command lines, stack traces, or parser internals; diagnostics may retain sanitized technical detail through the host-controlled diagnostics path.
