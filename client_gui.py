import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import socket
import threading

client_socket = None

def receive_messages(chat_display):
    while True:
        try:
            msg = client_socket.recv(1024).decode('utf-8')
            chat_display.config(state=tk.NORMAL)
            chat_display.insert(tk.END, "Server: " + msg + "\n")
            chat_display.config(state=tk.DISABLED)
        except:
            break

def send_message(message_entry):
    msg = message_entry.get()
    client_socket.send(msg.encode('utf-8'))
    message_entry.delete(0, tk.END)

def start_client():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 9999))

    root = tk.Tk()
    root.title("Client Chat")

    chat_display = scrolledtext.ScrolledText(root, state=tk.DISABLED)
    chat_display.pack(pady=10)

    message_entry = tk.Entry(root)
    message_entry.pack(pady=5)

    send_button = tk.Button(root, text="Send", command=lambda: send_message(message_entry))
    send_button.pack(pady=5)

    threading.Thread(target=receive_messages, args=(chat_display,)).start()

    root.mainloop()
    client_socket.close()

if __name__ == "__main__":
    start_client()
