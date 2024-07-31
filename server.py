import tkinter as tk
from tkinter import scrolledtext
import socket
import threading

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

    def accept_connections():
        while True:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, chat_display)).start()
            send_button.config(command=lambda cs=client_socket: send_message(cs, message_entry))

    threading.Thread(target=accept_connections).start()

    root.mainloop()
    server_socket.close()

if __name__ == "__main__":
    start_server()
