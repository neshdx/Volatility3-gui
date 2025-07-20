import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import datetime
import threading

# Globals to store the latest output and metadata
latest_output = ""
latest_mem_file = ""
latest_plugin = ""

def browse_file():
    file_path = filedialog.askopenfilename()
    entry_file.delete(0, tk.END)
    entry_file.insert(0, file_path)

def run_volatility():
    progress_bar.grid()
    progress_bar.start(10)
    text_output.delete(1.0, tk.END)
    summary_output.delete(1.0, tk.END)
    btn_download.config(state=tk.DISABLED)
    threading.Thread(target=execute_volatility).start()

def execute_volatility():
    global latest_output, latest_mem_file, latest_plugin

    mem_file = entry_file.get()
    plugin = entry_plugin.get()

    if not mem_file or not plugin:
        messagebox.showwarning("Input Error", "Please select a memory file and a plugin.")
        stop_progress()
        return

    cmd = ["python", "C:/Users/USER/volatility3/vol.py", "-f", mem_file, plugin]

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)

        latest_output = output
        latest_mem_file = mem_file
        latest_plugin = plugin

        text_output.insert(tk.END, output)
        summary = generate_summary(plugin, output)
        summary_output.insert(tk.END, summary)

        btn_download.config(state=tk.NORMAL)

    except subprocess.CalledProcessError as e:
        text_output.insert(tk.END, f"[ERROR]\n{e.output}")
        btn_download.config(state=tk.DISABLED)
    except FileNotFoundError:
        messagebox.showerror("Command Not Found", "The 'volatility3' command was not found.")
        btn_download.config(state=tk.DISABLED)
    finally:
        stop_progress()

def stop_progress():
    progress_bar.stop()
    progress_bar.grid_remove()

def download_report():
    global latest_output, latest_mem_file, latest_plugin

    if not latest_output:
        messagebox.showwarning("No Data", "Run a plugin first before downloading.")
        return

    base_name = os.path.basename(latest_mem_file)
    plugin_name = latest_plugin.replace("windows.", "").replace(".", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_filename = f"{base_name}_{plugin_name}_{timestamp}.txt"

    save_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        initialfile=output_filename,
        filetypes=[("Text Files", "*.txt")]
    )

    if save_path:
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(latest_output)
        messagebox.showinfo("Saved", f"Output saved to:\n{save_path}")

def generate_summary(plugin, output):
    lines = output.strip().splitlines()
    summary = f"Summary for {plugin}:\n"

    if plugin == "windows.pslist":
        process_count = len([line for line in lines if line.strip() and not line.startswith("PID")])
        summary += f"✔ Total processes found: {process_count}\n"

    elif plugin == "windows.netscan" or plugin == "windows.netstat":
        connection_count = len([line for line in lines if "ESTABLISHED" in line or "LISTEN" in line])
        summary += f"🔗 Network connections found: {connection_count}\n"
        if connection_count == 0:
            summary += "✔ No active connections found.\n"

    elif plugin == "windows.malfind":
        suspicious = len([line for line in lines if "Process" in line])
        summary += f"⚠ Potential injections: {suspicious}\n"
        if suspicious == 0:
            summary += "✔ No suspicious memory injections detected.\n"

    elif plugin == "windows.modules":
        module_count = len([line for line in lines if line.strip() and not line.startswith("Base")])
        summary += f"📦 Modules loaded: {module_count}\n"

    elif plugin == "windows.filescan":
        file_hits = len([line for line in lines if line.strip()])
        summary += f"📁 File scan results: {file_hits} hits\n"

    elif plugin == "windows.registry.hivelist":
        hive_count = len([line for line in lines if "Virtual" in line])
        summary += f"🗃 Registry hives listed: {hive_count}\n"

    elif plugin == "windows.dlllist":
        dll_lines = [line for line in lines if line.strip() and not line.startswith("PID")]
        summary += f"📄 DLLs listed: {len(dll_lines)}\n"

    else:
        summary += "ℹ No summary available for this plugin yet.\n"

    return summary + "\n"

# GUI Setup
root = tk.Tk()
root.title("Volatility 3 GUI")
root.geometry("1000x800")

tk.Label(root, text="Memory Dump File:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_file = tk.Entry(root, width=60)
entry_file.grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="Browse", command=browse_file).grid(row=0, column=2, padx=5, pady=5)

tk.Label(root, text="Select Plugin:").grid(row=1, column=0, padx=5, pady=5, sticky="e")

plugin_list = [
    "windows.pslist", "windows.pstree", "windows.netscan", "windows.netstat",
    "windows.cmdline", "windows.dlllist", "windows.filescan", "windows.handles",
    "windows.malfind", "windows.svcscan", "windows.sessions", "windows.modules",
    "windows.registry.hivelist", "windows.registry.printkey", "windows.getservicesids"
]

entry_plugin = ttk.Combobox(root, values=plugin_list, width=57)
entry_plugin.set("windows.pslist")
entry_plugin.grid(row=1, column=1, padx=5, pady=5)
tk.Button(root, text="Run", command=run_volatility).grid(row=1, column=2, padx=5, pady=5)

# Main Output
text_output = tk.Text(root, wrap="none", height=25)
text_output.grid(row=2, column=0, columnspan=3, padx=5, pady=10, sticky="nsew")

scroll_y = tk.Scrollbar(root, orient="vertical", command=text_output.yview)
scroll_y.grid(row=2, column=3, sticky='ns')
text_output.config(yscrollcommand=scroll_y.set)

scroll_x = tk.Scrollbar(root, orient="horizontal", command=text_output.xview)
scroll_x.grid(row=3, column=0, columnspan=3, sticky='ew')
text_output.config(xscrollcommand=scroll_x.set)

# Summary Output
tk.Label(root, text="Summary:").grid(row=4, column=0, padx=5, pady=0, sticky="nw")
summary_output = tk.Text(root, height=5, wrap="word", fg="green")
summary_output.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

# Progress Bar
progress_bar = ttk.Progressbar(root, mode='indeterminate')
progress_bar.grid(row=6, column=0, columnspan=2, padx=5, pady=10, sticky="ew")
progress_bar.grid_remove()

# Download Button
btn_download = tk.Button(root, text="Download Report", command=download_report, state=tk.DISABLED)
btn_download.grid(row=6, column=2, pady=10, sticky="e")

# Make GUI resizable
root.grid_rowconfigure(2, weight=2)
root.grid_rowconfigure(5, weight=1)
root.grid_columnconfigure(1, weight=1)

root.mainloop()
