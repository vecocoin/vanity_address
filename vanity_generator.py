import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import base58
import hashlib
from ecdsa import SigningKey, SECP256k1
import multiprocessing

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Coin network parameters
coin_params = {
    "veco":     {"addr_byte": b"\x46", "wif_byte": b"\x4B"},
    "litecoin": {"addr_byte": b"\x30", "wif_byte": b"\xB0"},
    "dash":     {"addr_byte": b"\x4C", "wif_byte": b"\xCC"},
    "2x2":      {"addr_byte": b"\x1C", "wif_byte": b"\x9C"},
    "poscoin":  {"addr_byte": b"\x37", "wif_byte": b"\xB7"},
    "bitcoin":  {"addr_byte": b"\x00", "wif_byte": b"\x80"},
}


# Generate CWIF and Address
def generate_cwif_and_address(addr_byte, wif_byte):
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    private_key_bytes = private_key.to_string()
    compress_byte = b'\x01'

    wif_payload = wif_byte + private_key_bytes + compress_byte
    wif_checksum = hashlib.sha256(hashlib.sha256(wif_payload).digest()).digest()[:4]
    cwif = base58.b58encode(wif_payload + wif_checksum).decode()

    public_key_compressed = public_key.to_string("compressed")
    sha256_hash = hashlib.sha256(public_key_compressed).digest()
    ripemd_hash = hashlib.new('ripemd160', sha256_hash).digest()
    addr_payload = addr_byte + ripemd_hash
    addr_checksum = hashlib.sha256(hashlib.sha256(addr_payload).digest()).digest()[:4]
    address = base58.b58encode(addr_payload + addr_checksum).decode()
    return cwif, address


def validate_targets(targets):
    invalid_targets = []
    for target in targets:
        for char in target:
            if char not in BASE58_ALPHABET:
                invalid_targets.append((target, char))
    if invalid_targets:
        msg = "\n".join(f"  • '{target}' contains invalid character: '{char}'" for target, char in invalid_targets)
        msg += "\n\n✔️ Valid Base58 characters are:\n"
        msg += "  " + BASE58_ALPHABET
        raise ValueError(f"🚫 Invalid characters found:\n\n{msg}")


# Address match function
def matches(address, targets, match_type, case_sensitive):
    address_cmp = address if case_sensitive else address.lower()
    for t in targets:
        t_cmp = t if case_sensitive else t.lower()
        if match_type == "prefix" and address_cmp.startswith(t_cmp):
            return True
        elif match_type == "suffix" and address_cmp.endswith(t_cmp):
            return True
        elif match_type == "anywhere" and t_cmp in address_cmp:
            return True
    return False


# Worker process
def worker(targets, addr_byte, wif_byte, match_type, case_sensitive, stop_flag, result_queue):
    while not stop_flag.value:
        cwif, address = generate_cwif_and_address(addr_byte, wif_byte)
        if matches(address, targets, match_type, case_sensitive):
            result_queue.put((cwif, address))
            stop_flag.value = True
            break


# GUI
def launch_gui():
    root = tk.Tk()
    root.title("Vanity Address Generator")

    # Frame for settings
    frm = ttk.Frame(root, padding=10)
    frm.grid(row=0, column=0, sticky="nsew")

    # Coin selector
    ttk.Label(frm, text="Select Coin:").grid(row=0, column=0, sticky="w")
    coin_var = tk.StringVar(value="veco")
    coin_menu = ttk.Combobox(frm, textvariable=coin_var, values=list(coin_params.keys()), state="readonly", width=15)
    coin_menu.grid(row=0, column=1, padx=5, pady=5, sticky="w")

    # Match type
    ttk.Label(frm, text="Match Type:").grid(row=0, column=2, sticky="w")
    match_var = tk.StringVar(value="prefix")
    match_menu = ttk.Combobox(frm, textvariable=match_var, values=["prefix", "suffix", "anywhere"], state="readonly", width=10)
    match_menu.grid(row=0, column=3, padx=5, pady=5, sticky="w")

    # Case sensitivity
    case_var = tk.BooleanVar(value=False)
    case_check = ttk.Checkbutton(frm, text="Case Sensitive", variable=case_var)
    case_check.grid(row=0, column=4, padx=5, pady=5, sticky="w")

    # Threads
    ttk.Label(frm, text="Threads:").grid(row=1, column=0, sticky="w")
    threads_var = tk.StringVar(value=str(multiprocessing.cpu_count()))
    ttk.Entry(frm, textvariable=threads_var, width=5).grid(row=1, column=1, sticky="w")

    # Targets
    ttk.Label(frm, text="Targets (one per line):").grid(row=2, column=0, columnspan=5, sticky="w", pady=(10, 0))
    targets_text = ScrolledText(frm, width=60, height=5)
    targets_text.grid(row=3, column=0, columnspan=5, pady=5)

    # Base58 Hint
    base58_hint = f"Valid Base58 characters: {BASE58_ALPHABET}"
    ttk.Label(frm, text=base58_hint, foreground="gray").grid(row=4, column=0, columnspan=5, sticky="w", padx=5)

    # Status
    ttk.Label(frm, text="Status:").grid(row=5, column=0, sticky="e")
    status_var = tk.StringVar(value="Idle")
    ttk.Label(frm, textvariable=status_var).grid(row=5, column=1, columnspan=4, sticky="w")

    # Results
    result_var = tk.StringVar()
    cwif_var = tk.StringVar()
    ttk.Label(frm, text="Address:").grid(row=6, column=0, sticky="e")
    ttk.Entry(frm, textvariable=result_var, width=50, state="readonly").grid(row=6, column=1, columnspan=4, sticky="w")
    ttk.Label(frm, text="CWIF:").grid(row=7, column=0, sticky="e")
    ttk.Entry(frm, textvariable=cwif_var, width=50, state="readonly").grid(row=7, column=1, columnspan=4, sticky="w")

    def start_search():
        nonlocal processes
        try:
            thread_count = int(threads_var.get())
            if thread_count <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number of threads.")
            return

        selected_coin = coin_var.get()
        if selected_coin not in coin_params:
            messagebox.showerror("Invalid Coin", "Selected coin is not supported.")
            return

        targets = [t.strip() for t in targets_text.get("1.0", "end").splitlines() if t.strip()]
        if not targets:
            messagebox.showerror("Missing Targets", "Please enter at least one target string.")
            return

        #Validate Base58 targets
        try:
            validate_targets(targets)
        except ValueError as e:
            messagebox.showerror("Invalid Characters", str(e))
            return

        addr_byte = coin_params[selected_coin]["addr_byte"]
        wif_byte = coin_params[selected_coin]["wif_byte"]
        match_type = match_var.get()
        case_sensitive = case_var.get()

        result_var.set("")
        cwif_var.set("")
        status_var.set("Running")
        start_btn["state"] = "disabled"
        stop_btn["state"] = "normal"
        copy_btn["state"] = "disabled"
        coin_menu["state"] = match_menu["state"] = "disabled"
        case_check["state"] = "disabled"
        targets_text["state"] = "disabled"

        stop_flag.value = False
        for _ in range(thread_count):
            p = multiprocessing.Process(target=worker, args=(targets, addr_byte, wif_byte, match_type, case_sensitive, stop_flag, result_queue))
            p.start()
            processes.append(p)

        root.after(100, poll_result)

    def poll_result():
        if not result_queue.empty():
            cwif, address = result_queue.get()
            cwif_var.set(cwif)
            result_var.set(address)
            status_var.set("Done")
            enable_controls()
        elif stop_flag.value:
            status_var.set("Stopped")
            enable_controls()
        else:
            root.after(100, poll_result)

    def stop_search():
        stop_flag.value = True
        status_var.set("Stopping...")

    def copy_result():
        root.clipboard_clear()
        root.clipboard_append(f"{result_var.get()}\n{cwif_var.get()}")
        root.update()
        messagebox.showinfo("Copied", "Address and CWIF copied to clipboard.")

    def enable_controls():
        start_btn["state"] = "normal"
        stop_btn["state"] = "disabled"
        copy_btn["state"] = "normal"
        coin_menu["state"] = match_menu["state"] = "readonly"
        case_check["state"] = "normal"
        targets_text["state"] = "normal"

    processes = []

    ttk.Separator(frm, orient="horizontal").grid(row=8, column=0, columnspan=5, sticky="ew", pady=(10, 0))
    btn_frame = ttk.Frame(frm)
    btn_frame.grid(row=9, column=0, columnspan=5, pady=10)

    # Buttons
    btn_frame = ttk.Frame(frm)
    btn_frame.grid(row=9, column=0, columnspan=5, pady=10)  
    start_btn = ttk.Button(btn_frame, text="Start Search", command=start_search)
    start_btn.pack(side="left", padx=5)
    stop_btn = ttk.Button(btn_frame, text="Stop", command=stop_search, state="disabled")
    stop_btn.pack(side="left", padx=5)
    copy_btn = ttk.Button(btn_frame, text="Copy to Clipboard", command=copy_result, state="disabled")
    copy_btn.pack(side="left", padx=5)

    root.mainloop()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    manager = multiprocessing.Manager()
    stop_flag = manager.Value('b', False)
    result_queue = manager.Queue()
    launch_gui()
