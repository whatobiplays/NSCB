# Keep stable machine output except for Plan snapshots

NSCB's normal JSON and JSONL result/event surfaces remain explicitly versioned compatibility contracts. Every normal machine-readable document/record includes a stable top-level `schema_version` and `kind`, plus the producing `nscb_version` where useful; consumers dispatch on schema/kind rather than parsing human-facing text. Serialized Plan snapshots are a deliberate exception: they identify their output kind and producing NSCB version yet carry no cross-version schema or replay guarantee.

`--json` emits exactly one structured success or handled-error document on stdout and uses the stable process exit class for outcome; `--jsonl` emits typed semantic records and ends every normally handled execution with exactly one authoritative terminal result record. Human and technical diagnostics remain on stderr rather than contaminating machine-readable stdout.

v1 freezes these numeric process exit classes: `0` success, `2` usage/configuration, `3` prerequisite/input, `4` conflict, `5` provider/device, `6` cancelled/interrupted, `7` internal failure, and `8` completed-with-issues. Detailed stable error codes remain in structured output and may evolve additively under the public compatibility contract.
