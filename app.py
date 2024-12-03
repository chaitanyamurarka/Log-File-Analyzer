import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import re
import csv
from collections import defaultdict

# Constants
RESULTS_FOLDER = "results"
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# Regular expressions for parsing log entries
ip_regex = r'(\d+\.\d+\.\d+\.\d+)'  # IP address
endpoint_regex = r'"[A-Z]+ (/[^\s]*)'  # Endpoint
status_code_regex = r'HTTP/\d\.\d" (\d+)'  # HTTP status code


def analyze_log_file(log_file, threshold):
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    # Parse the log file
    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP addresses
            ip_match = re.search(ip_regex, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_counts[ip] += 1

            # Extract endpoints
            endpoint_match = re.search(endpoint_regex, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1

            # Detect failed login attempts
            status_match = re.search(status_code_regex, line)
            if status_match:
                status_code = status_match.group(1)
                if status_code == '401':  # Look for HTTP status 401
                    failure_message = "Invalid credentials"
                    if failure_message in line:
                        if ip_match:
                            ip = ip_match.group(1)
                            failed_login_attempts[ip] += 1

    # Sort results
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_endpoint_counts = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
    suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > threshold]

    return sorted_ip_counts, sorted_endpoint_counts, suspicious_ips


def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log")])
    if file_path:
        log_file_entry.delete(0, tk.END)
        log_file_entry.insert(0, file_path)


def process_log():
    log_file = log_file_entry.get()
    if not os.path.isfile(log_file):
        messagebox.showerror("Error", "Please select a valid log file.")
        return

    try:
        threshold = int(threshold_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for the threshold.")
        return

    sorted_ip_counts, sorted_endpoint_counts, suspicious_ips = analyze_log_file(log_file, threshold)

    # Display results in the text box
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, "===== IP Address Request Count =====\n", "header")
    for ip, count in sorted_ip_counts:
        results_text.insert(tk.END, f"{ip: <20} | {count}\n")

    results_text.insert(tk.END, "\n===== Most Frequently Accessed Endpoint =====\n", "header")
    if sorted_endpoint_counts:
        endpoint, count = sorted_endpoint_counts[0]
        results_text.insert(tk.END, f"{endpoint} (Accessed {count} times)\n")
    else:
        results_text.insert(tk.END, "No endpoint data available.\n")

    results_text.insert(tk.END, "\n===== Suspicious Activity Detected =====\n", "header")
    if suspicious_ips:
        for ip, count in suspicious_ips:
            results_text.insert(tk.END, f"{ip: <20} | {count} failed login attempts\n")
    else:
        results_text.insert(tk.END, "No suspicious activity detected.\n")

    # Save results to a CSV file
    results_csv_path = os.path.join(RESULTS_FOLDER, "log_analysis_results.csv")
    with open(results_csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(sorted_ip_counts)

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        if sorted_endpoint_counts:
            writer.writerow(sorted_endpoint_counts[0])

        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips)

    results_text.insert(tk.END, f"\nResults saved to: {results_csv_path}\n", "success")


# Create the main window
root = tk.Tk()
root.title("Log File Analyzer")
root.configure(bg="#f0f0f0")

# Define styles
header_font = ("Helvetica", 12, "bold")
normal_font = ("Helvetica", 10)
success_font = ("Helvetica", 10, "italic")

# Log file selection
tk.Label(root, text="Log File:", bg="#f0f0f0", font=normal_font).grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
log_file_entry = tk.Entry(root, width=50)
log_file_entry.grid(row=0, column=1, padx=10, pady=10)
browse_button = tk.Button(root, text="Browse", command=browse_file, bg="#d9d9d9")
browse_button.grid(row=0, column=2, padx=10, pady=10)

# Threshold input
tk.Label(root, text="Failed Login Threshold:", bg="#f0f0f0", font=normal_font).grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
threshold_entry = tk.Entry(root, width=10)
threshold_entry.insert(0, "10")
threshold_entry.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)

# Analyze button
analyze_button = tk.Button(root, text="Analyze Log", command=process_log, bg="#d9d9d9")
analyze_button.grid(row=2, column=1, pady=10)

# Results display
results_frame = tk.Frame(root, bg="#f0f0f0")
results_frame.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

scrollbar = tk.Scrollbar(results_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

results_text = tk.Text(results_frame, height=20, width=80, yscrollcommand=scrollbar.set, font=normal_font)
results_text.pack()
scrollbar.config(command=results_text.yview)

# Tag configurations
results_text.tag_configure("header", font=header_font, foreground="blue")
results_text.tag_configure("success", font=success_font, foreground="green")

# Run the Tkinter main loop
root.mainloop()
