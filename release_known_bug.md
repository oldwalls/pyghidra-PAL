

## Known deferred release bug: TLS stack-canary alias leak

#### in alpha_corpo.exe & o3_alpha_corpo.exe specimen runs

The two instances were patched by hand, to reflect `abi_tls_base`

PALPHIfolder.py & PALemitter.py debug to follow

---
In this function, PAL correctly resolves the TLS base at entry:

```python
abi_tls_base = c_abi_get(abi_context, 'tls_base', 'FS_OFFSET', 64)
```

but the stack-canary epilogue later emits:

```python
v_168 = c_load(MEM, c_add(in_FS_OFFSET, 0x28, 64), 64)
```

`in_FS_OFFSET` is an unresolved Ghidra-origin identifier with no executable PAL binding. The correct semantic source is the already-established `abi_tls_base`.

This is a localized emitter/alias-propagation defect in stack-canary reconstruction, not a control-flow or state-machine recovery failure. In affected functions it causes an undefined-name failure at the canary check and prevents normal completion.

Status for release: **known, reproducible, deferred**. The pre-alpha release will document it rather than patch it late. The intended future correction is identity-backed reuse of the established TLS ABI alias in all later canary loads, without textual name substitution.
