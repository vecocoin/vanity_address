# Vanity Address Generator (GUI)

A lightweight and user-friendly GUI tool to generate **vanity addresses** for UTXO-based cryptocurrencies (e.g. VECO, Litecoin, Dash, 2X2, Bitcoin, etc.).  
Supports parallel processing, multiple targets, and Base58 validation.

---

## Features

- Supports multiple UTXO coins (VECO, LTC, Dash, etc.)
- Multi-threaded address generation
- Match prefix, suffix, or any substring
- Toggle case sensitivity
- GUI interface with clipboard copy and live status
- Validates targets against Base58 alphabet

---

## Screenshots
![Screenshot1](assets/screenshot1.png)
![Screenshot2](assets/screenshot2.png)
![Screenshot3](assets/screenshot3.png)

---

## Important Notes

- Each additional character increases difficulty by **~58x** when case sensitivity is enabled.
- **Complex patterns** (e.g. full words) can take a long time.
- The **prefix must match the address style of the coin**. For example:
  - `V` for **VECO**
  - `L` for **Litecoin**
  - `X` for **Dash**
  - etc.

If your pattern does not start with a valid prefix for that coin, **it will never be found**.

---

## Importing your Private Keys (CWIFs)

Once you find a matching address and corresponding CWIF (private key), you can import it into your full node wallet via the debug console:

`importprivkey “yourCWIFkey” “” false`

The `false` at the end disables rescanning for historical transactions (faster).

You may optionally replace the empty string `""` with a label:

`importprivkey “yourCWIFkey” “label” false`

For the web wallet or lite wallet simply use the import wallet function.

---

## Tips

To maximize performance:

- Run with multiple CPU threads
- Use shorter and simpler targets 
- Disable case sensitivity if not necessary

---

## Build

If you want to build this as an executable (e.g. `.exe` on Windows):

```bash
pip install pyinstaller ecdsa base58
pyinstaller --noconfirm --clean --windowed --name=vanity_gui --collect-submodules=ecdsa --collect-submodules=base58 vanity_gui.py
```

## License

MIT – do whatever you like, just don’t blame me if you lose coins.
