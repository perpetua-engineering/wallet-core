# Cryptograph Fork Changelog

This file tracks modifications made to Trust Wallet Core for the Cryptograph project.
Base version: wallet-core 4.x (see git history for exact commit)

---

## 2025-12-29

### Security: Zero TWData buffers on delete (CR-163)

**File:** `src/interface/TWData.cpp`

**Change:** Added `memzero()` call in `TWDataDelete()` to zero buffer contents before freeing.

**Rationale:** `TWStringDelete` already zeros memory before delete, but `TWDataDelete` did not.
This asymmetry meant that sensitive data (private key bytes, seeds) passed through the C bridging
layer via TWData would linger in freed memory. Now both APIs have consistent secure cleanup.

**Diff:**
```cpp
void TWDataDelete(TWData *_Nonnull data) {
    auto* v = const_cast<Data*>(reinterpret_cast<const Data*>(data));
+   // Security: Zero sensitive data before freeing (matches TWStringDelete behavior)
+   memzero(v->data(), v->size());
    delete v;
}
```

**References:**
- CR-163: Security Audit: WalletCore Swift Overlay & C++ Library
- CR-146: WalletCore dependency upgrade audit process
