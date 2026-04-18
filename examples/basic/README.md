# Basic Example

This example runs read-only SDK calls against a Nessus Manager instance and
writes local raw/API and SDK/model output side by side.

By default it reads the repository-root `.nessus.json` file:

```bash
go run ./examples/basic
```

To use a separate config:

```bash
cp examples/basic/config.example.json examples/basic/config.local.json
$EDITOR examples/basic/config.local.json
go run ./examples/basic -config examples/basic/config.local.json
```

Output is written under:

```text
examples/basic/output/raw
examples/basic/output/sdk
examples/basic/output/compare
```

Use the raw files to check what the Nessus API returned and the SDK files to
check what the public models preserved. Compare files list raw item keys, SDK
item keys, and raw keys not represented by the SDK model. The output directory
is ignored by git.
