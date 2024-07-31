import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import socket
import threading
import queue
from user_auth import register_user, login_user

def handle_client(client_socket, chat_display):
    while True:
        try:
            msg = client_socket.recv(1024).decode('utf-8')
            chat_display.config(state=tk.NORMAL)
            chat_display.insert(tk.END, "Client: " + msg + "\n")
            chat_display.config(state=tk.DISABLED)
        except:
            break

def send_message(client_socket, message_entry):
    msg = message_entry.get()
    client_socket.send(msg.encode('utf-8'))
    message_entry.delete(0, tk.END)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 9999))
    server_socket.listen()

    root = tk.Tk()
    root.title("Server Chat")

    chat_display = scrolledtext.ScrolledText(root, state=tk.DISABLED)
    chat_display.pack(pady=10)

    message_entry = tk.Entry(root)
    message_entry.pack(pady=5)

    send_button = tk.Button(root, text="Send")
    send_button.pack(pady=5)

    # Queue for communicating between threads
    client_queue = queue.Queue()

    def accept_connections():
        while True:
            client_socket, addr = server_socket.accept()
            client_queue.put(client_socket)

    def process_client():
        if not client_queue.empty():
            client_socket = client_queue.get()
            # Perform user authentication
            auth_window = tk.Toplevel(root)
            auth_window.title("User Authentication")
            
            def handle_login():
                username = simpledialog.askstring("Login", "Enter Username:", parent=auth_window)
                password = simpledialog.askstring("Login", "Enter Password:", parent=auth_window, show='*')
                if login_user(username, password):
                    messagebox.showinfo("Login", "Login Successful!")
                    auth_window.destroy()
                    threading.Thread(target=handle_client, args=(client_socket, chat_display)).start()
                    send_button.config(command=lambda: send_message(client_socket, message_entry))
                else:
                    messagebox.showerror("Login", "Login Failed!")

            def handle_register():
                username = simpledialog.askstring("Register", "Enter Username:", parent=auth_window)
                password = simpledialog.askstring("Register", "Enter Password:", parent=auth_window, show='*')
                if register_user(username, password):
                    messagebox.showinfo("Register", "Registration Successful!")
                else:
                    messagebox.showerror("Register", "Username already exists!")

            login_button = tk.Button(auth_window, text="Login", command=handle_login)
            login_button.pack(pady=5)
            
            register_button = tk.Button(auth_window, text="Register", command=handle_register)
            register_button.pack(pady=5)

        root.after(100, process_client)  # Check the queue every 100 ms

    threading.Thread(target=accept_connections, daemon=True).start()
    root.after(100, process_client)  # Start the periodic check

    root.mainloop()
    server_socket.close()

if __name__ == "__main__":
    start_server()
