import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, Listbox
import socket
import threading
import queue
from user_auth import register_user, login_user

def handle_client(client_socket, chat_display, user_list, username):
    while True:
        try:
            msg = client_socket.recv(1024).decode('utf-8')
            if msg:
                chat_display.config(state=tk.NORMAL)
                chat_display.insert(tk.END, f"{username}: {msg}\n")
                chat_display.config(state=tk.DISABLED)
            else:
                break
        except:
            break
    user_list.delete(user_list.get(0, tk.END).index(username))
    client_socket.close()

def send_message(client_socket, message_entry, username, chat_display):
    msg = message_entry.get()
    client_socket.send(msg.encode('utf-8'))
    message_entry.delete(0, tk.END)
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, f"You: {msg}\n")
    chat_display.config(state=tk.DISABLED)

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

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 9999))
    server_socket.listen()

    root = tk.Tk()
    root.title("Server Chat")
    root.geometry("600x500")
    root.configure(bg="#2b2b2b")

    header = tk.Label(root, text="Server Chat", bg="#2b2b2b", fg="white", font=("Helvetica", 16, "bold"))
    header.pack(pady=10)

    main_frame = tk.Frame(root, bg="#2b2b2b")
    main_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    chat_display = scrolledtext.ScrolledText(main_frame, state=tk.DISABLED, bg="#1e1e1e", fg="white", font=("Helvetica", 12))
    chat_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

    user_list = Listbox(main_frame, bg="#1e1e1e", fg="white", font=("Helvetica", 12))
    user_list.pack(side=tk.RIGHT, fill=tk.Y)

    message_frame = tk.Frame(root, bg="#2b2b2b")
    message_frame.pack(pady=5, padx=10, fill=tk.X)

    message_entry = tk.Entry(message_frame, bg="#3c3c3c", fg="white", font=("Helvetica", 12))
    message_entry.pack(side=tk.LEFT, pady=5, padx=(0, 5), fill=tk.X, expand=True)

    send_button = tk.Button(message_frame, text="Send", bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
    send_button.pack(side=tk.RIGHT, pady=5)

    client_queue = queue.Queue()

    def accept_connections():
        while True:
            client_socket, addr = server_socket.accept()
            client_queue.put(client_socket)

    def process_client():
        if not client_queue.empty():
            client_socket = client_queue.get()
            auth_window = tk.Toplevel(root)
            auth_window.title("User Authentication")
            auth_window.geometry("300x200")
            auth_window.configure(bg="#2b2b2b")
            
            header = tk.Label(auth_window, text="User Authentication", bg="#2b2b2b", fg="white", font=("Helvetica", 14, "bold"))
            header.pack(pady=10)

            def handle_login():
                username = create_custom_dialog("Login", "Enter Username:")
                password = create_custom_dialog("Login", "Enter Password:", is_password=True)
                if login_user(username, password):
                    messagebox.showinfo("Login", "Login Successful!")
                    auth_window.destroy()
                    user_list.insert(tk.END, username)
                    threading.Thread(target=handle_client, args=(client_socket, chat_display, user_list, username)).start()
                    send_button.config(command=lambda: send_message(client_socket, message_entry, username, chat_display))
                else:
                    messagebox.showerror("Login", "Login Failed!")

            def handle_register():
                username = create_custom_dialog("Register", "Enter Username:")
                password = create_custom_dialog("Register", "Enter Password:", is_password=True)
                if register_user(username, password):
                    messagebox.showinfo("Register", "Registration Successful!")
                else:
                    messagebox.showerror("Register", "Username already exists!")

            login_button = tk.Button(auth_window, text="Login", command=handle_login, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
            login_button.pack(pady=10)

            register_button = tk.Button(auth_window, text="Register", command=handle_register, bg="#008CBA", fg="white", font=("Helvetica", 12, "bold"))
            register_button.pack(pady=10)

        root.after(100, process_client)

    threading.Thread(target=accept_connections, daemon=True).start()
    root.after(100, process_client)

    root.mainloop()
    server_socket.close()

if __name__ == "__main__":
    start_server()
