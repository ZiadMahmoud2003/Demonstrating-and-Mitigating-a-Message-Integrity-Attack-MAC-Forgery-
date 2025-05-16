import customtkinter as ctk
import tkinter as tk
from server import generate_mac as md5_generate_mac, verify as md5_verify
from server_hmac import generate_mac as hmac_generate_mac, verify as hmac_verify
from client import md5_padding, parse_md5_hexdigest, MIN_KEY_LEN, MAX_KEY_LEN, append_data, intercepted_message, intercepted_mac
import pymd5

try:
    from customtkinter import CTkMessageBox
    def show_alert(title, message):
        CTkMessageBox(title=title, message=message)
except ImportError:
    from tkinter import messagebox
    def show_alert(title, message):
        messagebox.showinfo(title, message)

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class MACGui(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("MAC Attack Demo GUI")
        self.geometry("750x540")
        self.resizable(False, False)

        # Title label
        self.title_label = ctk.CTkLabel(self, text="MAC Security Demo", font=("Arial", 24, "bold"))
        self.title_label.pack(pady=(10, 0))

        self.tabview = ctk.CTkTabview(self, width=720, height=470)
        self.tabview.pack(padx=10, pady=10)

        self.md5_tab = self.tabview.add("MD5 (Insecure)")
        self.hmac_tab = self.tabview.add("HMAC (Secure)")

        self.build_md5_tab()
        self.build_hmac_tab()

    def build_md5_tab(self):
        # Message input
        self.md5_message_label = ctk.CTkLabel(self.md5_tab, text="Message:", font=("Arial", 14))
        self.md5_message_label.place(x=20, y=20)
        self.md5_message_entry = ctk.CTkEntry(self.md5_tab, width=420, font=("Arial", 13))
        self.md5_message_entry.place(x=120, y=20)
        self.md5_message_entry.insert(0, "hello_world")

        # MAC input
        self.md5_mac_label = ctk.CTkLabel(self.md5_tab, text="MAC:", font=("Arial", 14))
        self.md5_mac_label.place(x=20, y=60)
        self.md5_mac_entry = ctk.CTkEntry(self.md5_tab, width=420, font=("Arial", 13))
        self.md5_mac_entry.place(x=120, y=60)

        # Output box
        self.md5_output = ctk.CTkTextbox(self.md5_tab, width=680, height=230, font=("Consolas", 12))
        self.md5_output.place(x=20, y=150)

        # Button frame for better layout
        self.md5_btn_frame = ctk.CTkFrame(self.md5_tab, fg_color="transparent")
        self.md5_btn_frame.place(x=20, y=105)
        self.md5_gen_btn = ctk.CTkButton(self.md5_btn_frame, text="Generate MAC", command=self.md5_generate_mac, width=140)
        self.md5_gen_btn.grid(row=0, column=0, padx=5)
        self.md5_verify_btn = ctk.CTkButton(self.md5_btn_frame, text="Verify MAC", command=self.md5_verify_mac, width=140)
        self.md5_verify_btn.grid(row=0, column=1, padx=5)
        self.md5_attack_btn = ctk.CTkButton(self.md5_btn_frame, text="Length Extension Attack", command=self.md5_attack, width=180)
        self.md5_attack_btn.grid(row=0, column=2, padx=15)
        self.md5_clear_btn = ctk.CTkButton(self.md5_btn_frame, text="Clear", command=self.md5_clear, width=80)
        self.md5_clear_btn.grid(row=0, column=3, padx=15)

    def build_hmac_tab(self):
        self.hmac_message_label = ctk.CTkLabel(self.hmac_tab, text="Message:", font=("Arial", 14))
        self.hmac_message_label.place(x=20, y=20)
        self.hmac_message_entry = ctk.CTkEntry(self.hmac_tab, width=420, font=("Arial", 13))
        self.hmac_message_entry.place(x=120, y=20)
        self.hmac_message_entry.insert(0, "hello_world")

        self.hmac_mac_label = ctk.CTkLabel(self.hmac_tab, text="MAC:", font=("Arial", 14))
        self.hmac_mac_label.place(x=20, y=60)
        self.hmac_mac_entry = ctk.CTkEntry(self.hmac_tab, width=420, font=("Arial", 13))
        self.hmac_mac_entry.place(x=120, y=60)

        self.hmac_output = ctk.CTkTextbox(self.hmac_tab, width=680, height=230, font=("Consolas", 12))
        self.hmac_output.place(x=20, y=150)

        self.hmac_btn_frame = ctk.CTkFrame(self.hmac_tab, fg_color="transparent")
        self.hmac_btn_frame.place(x=20, y=105)
        self.hmac_gen_btn = ctk.CTkButton(self.hmac_btn_frame, text="Generate HMAC", command=self.hmac_generate_mac, width=140)
        self.hmac_gen_btn.grid(row=0, column=0, padx=5)
        self.hmac_verify_btn = ctk.CTkButton(self.hmac_btn_frame, text="Verify HMAC", command=self.hmac_verify_mac, width=140)
        self.hmac_verify_btn.grid(row=0, column=1, padx=5)
        self.hmac_attack_btn = ctk.CTkButton(self.hmac_btn_frame, text="Length Extension Attack", command=self.hmac_attack, width=180)
        self.hmac_attack_btn.grid(row=0, column=2, padx=15)
        self.hmac_clear_btn = ctk.CTkButton(self.hmac_btn_frame, text="Clear", command=self.hmac_clear, width=80)
        self.hmac_clear_btn.grid(row=0, column=3, padx=15)

    def md5_generate_mac(self):
        msg = self.md5_message_entry.get().encode()
        mac = md5_generate_mac(msg)
        self.md5_mac_entry.delete(0, tk.END)
        self.md5_mac_entry.insert(0, mac)
        self.md5_output.insert(tk.END, f"Generated MAC: {mac}\n")

    def md5_verify_mac(self):
        msg = self.md5_message_entry.get().encode()
        mac = self.md5_mac_entry.get()
        valid = md5_verify(msg, mac)
        self.md5_output.insert(tk.END, f"MAC verification: {'Valid' if valid else 'Invalid'}\n")

    def md5_attack(self):
        import io, sys
        old_stdout = sys.stdout
        sys.stdout = mystdout = io.StringIO()
        try:
            from client import perform_attack
            perform_attack()
        except Exception as e:
            print(f"Attack error: {e}")
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        self.md5_output.insert(tk.END, output + "\n")
        if "[SUCCESS]" in output:
            show_alert("Attack Result", "Success! Length extension attack worked.")
        else:
            show_alert("Attack Result", "Fail. Length extension attack did not work.")

    def md5_clear(self):
        self.md5_message_entry.delete(0, tk.END)
        self.md5_mac_entry.delete(0, tk.END)
        self.md5_output.delete("1.0", tk.END)

    def hmac_generate_mac(self):
        msg = self.hmac_message_entry.get().encode()
        mac = hmac_generate_mac(msg)
        self.hmac_mac_entry.delete(0, tk.END)
        self.hmac_mac_entry.insert(0, mac)
        self.hmac_output.insert(tk.END, f"Generated HMAC: {mac}\n")

    def hmac_verify_mac(self):
        msg = self.hmac_message_entry.get().encode()
        mac = self.hmac_mac_entry.get()
        valid = hmac_verify(msg, mac)
        self.hmac_output.insert(tk.END, f"HMAC verification: {'Valid' if valid else 'Invalid'}\n")

    def hmac_attack(self):
        # Try the same length extension attack logic as MD5, but verify with HMAC
        output_lines = []
        success = False
        for key_len in range(MIN_KEY_LEN, MAX_KEY_LEN + 1):
            orig_len = key_len + len(intercepted_message)
            padding = md5_padding(orig_len)
            forged_message = intercepted_message + padding + append_data
            state = parse_md5_hexdigest(intercepted_mac)
            total_len = orig_len + len(padding)
            m = pymd5.md5(state=state, count=total_len*8)
            m.update(append_data)
            forged_mac = m.hexdigest()
            output_lines.append(f"Trying key length: {key_len}")
            output_lines.append(f"Forged message (hex): {forged_message.hex()}")
            output_lines.append(f"Forged MAC: {forged_mac}")
            if hmac_verify(forged_message, forged_mac):
                output_lines.append(f"[SUCCESS] Forged MAC is valid! Key length: {key_len}")
                output_lines.append(f"Forged message: {forged_message}")
                success = True
                break
            else:
                output_lines.append("[FAIL] Forged MAC is not valid.")
        if not success:
            output_lines.append("Tried all key lengths, none succeeded.")
        self.hmac_output.insert(tk.END, "\n".join(output_lines) + "\n")
        if success:
            show_alert("Attack Result", "Success! (Unexpected) Length extension attack worked on HMAC.")
        else:
            show_alert("Attack Result", "Fail. HMAC is secure against length extension attacks.")

    def hmac_clear(self):
        self.hmac_message_entry.delete(0, tk.END)
        self.hmac_mac_entry.delete(0, tk.END)
        self.hmac_output.delete("1.0", tk.END)

if __name__ == "__main__":
    app = MACGui()
    app.mainloop() 