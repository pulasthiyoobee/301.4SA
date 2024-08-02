import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import socket
import threading

def receive_messages(client_socket, chat_frame):
    while True:
        try:
            msg = client_socket.recv(1024).decode('utf-8')
            add_chat_bubble(chat_frame, msg, "server")
        except:
            break

def send_message(client_socket, message_entry, chat_frame):
    msg = message_entry.get()
    if msg.strip():
        client_socket.send(msg.encode('utf-8'))
        add_chat_bubble(chat_frame, msg, "client")
        message_entry.delete(0, tk.END)
    else:
        messagebox.showwarning("Warning", "Cannot send empty message")

def create_custom_dialog(title, prompt, is_password=False):
    dialog = tk.Toplevel()
    dialog.title(title)
    dialog.geometry("300x150")
    dialog.configure(bg="#2b2b2b")
    
    prompt_label = tk.Label(dialog, text=prompt, bg="#2b2b2b", fg="white", font=("Helvetica", 12))
    prompt_label.pack(pady=10)

    entry = tk.Entry(dialog, bg="#3c3c3c", fg="white", font=("Helvetica", 12), show="*" if is_password else "")
    entry.pack(pady=5)

    def on_submit():
        dialog.result = entry.get()
        dialog.destroy()

    submit_button = tk.Button(dialog, text="Submit", bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"), command=on_submit)
    submit_button.pack(pady=10)

    dialog.grab_set()
    dialog.wait_window()

    return getattr(dialog, 'result', None)

def logout(client_socket, root):
    client_socket.close()
    root.destroy()

def add_chat_bubble(chat_frame, message, sender):
    bubble_frame = tk.Frame(chat_frame, bg="#2b2b2b")
    bubble_frame.pack(fill=tk.X, pady=5, padx=10, anchor='w' if sender == "server" else 'e')

    if sender == "server":
        bubble = tk.Label(bubble_frame, text=message, bg="#3c3c3c", fg="white", font=("Helvetica", 12), wraplength=250, justify=tk.LEFT, anchor='w', padx=10, pady=5)
    else:
        bubble = tk.Label(bubble_frame, text=message, bg="#4CAF50", fg="white", font=("Helvetica", 12), wraplength=250, justify=tk.RIGHT, anchor='e', padx=10, pady=5)
    
    bubble.pack(side=tk.LEFT if sender == "server" else tk.RIGHT, fill=tk.X)

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 9999))

    root = tk.Tk()
    root.title("Client Chat")
    root.geometry("400x500")
    root.configure(bg="#2b2b2b")

    header_frame = tk.Frame(root, bg="#2b2b2b")
    header_frame.pack(pady=10, fill=tk.X)

    header = tk.Label(header_frame, text="Client Chat", bg="#2b2b2b", fg="white", font=("Helvetica", 16, "bold"))
    header.pack(side=tk.LEFT, padx=(10, 0))

    logout_button = tk.Button(header_frame, text="Logout", bg="#f44336", fg="white", font=("Helvetica", 12, "bold"), command=lambda: logout(client_socket, root))
    logout_button.pack(side=tk.RIGHT, padx=(0, 10))

    chat_frame = tk.Frame(root, bg="#1e1e1e")
    chat_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    message_frame = tk.Frame(root, bg="#2b2b2b")
    message_frame.pack(pady=5, padx=10, fill=tk.X)

    message_entry = tk.Entry(message_frame, bg="#3c3c3c", fg="white", font=("Helvetica", 12))
    message_entry.pack(side=tk.LEFT, pady=5, padx=(0, 5), fill=tk.X, expand=True)

    send_button = tk.Button(message_frame, text="Send", bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"), 
                            command=lambda: send_message(client_socket, message_entry, chat_frame))
    send_button.pack(side=tk.RIGHT, pady=5)

    threading.Thread(target=receive_messages, args=(client_socket, chat_frame), daemon=True).start()

    root.mainloop()
    client_socket.close()

if __name__ == "__main__":
    start_client()
