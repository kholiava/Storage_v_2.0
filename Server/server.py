import os
import ssl
import logging
import sys
import hashlib, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import json
import time
import random
from threading import Thread
import string

import server_commands, client_commands


class Session(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.all_sessions = dict()
        self.time_inactivity = 15 * 60

    def create(self, user_name):
        while True:
            session_key = random.sample(string.ascii_letters + string.digits, 40)
            session_key = ''.join(session_key)
            if self.all_sessions.get(session_key) is None:
                break
        data = dict(user=user_name, last_time=time.time())
        self.all_sessions.update([(session_key, data)])
        return session_key

    def update(self, session_key):
        self.all_sessions[session_key]['last_time'] = time.time()

    def delete(self, session_key):
        self.all_sessions.pop(session_key)

    def run(self):
        while True:
            time.sleep(self.time_inactivity / 2)
            ses_del = []
            for ses in self.all_sessions.keys():
                if (time.time() - self.all_sessions[ses]['last_time']) > self.time_inactivity:
                    ses_del.append(ses)
            for ses in ses_del:
                    self.delete(ses)


class MyHTTPServer(ThreadingMixIn, HTTPServer):
    session = Session()


class ChunkedHTTPRequestHandler(BaseHTTPRequestHandler):
    """"HTTP 1.1 Chunked encoding request handler"""
    # Use HTTP 1.1 as 1.0 doesn't support chunked encoding
    protocol_version = "HTTP/1.1"

    def query_get(self, queryData, key, default=""):
        """Helper for getting values from a pre-parsed query string"""
        return queryData.get(key, [default])[0]

    def do_GET(self):
        logging.info('New command <{command}> from client {address}'.format(command=self.path, address=self.address_string()))

        if self.path == '/list':
            # отримуємо ключ сесії
            session_key = self.headers.get('Cookie')
            # перевіряємо чи ключ сесії був переданий
            if session_key == None or session_key == '' :
                msg = 'Error: You must login first.'
                self.send_response_only(400, msg)
            else:
                # перевіряємо чи дійсна сесія
                if self.server.session.all_sessions.get(session_key):
                    # оновлюємо час останньої активності
                    self.server.session.update(session_key)
                    # визначаємо ім'я користувача по ключу сесії
                    username = self.server.session.all_sessions[session_key]['user']
                    # визначаємо директорію користувача
                    user_dir = os.path.join(STORAGE_PATH, username)
                    # визначаємо всі файли, які лежать в директорії користувача
                    user_files = os.listdir(user_dir)
                    msg = str(user_files)
                    self.send_response_only(200, msg)
                    msg = 'User "{user}": command <{command}> done successfully.'.format(user=username, command=self.path)
                else:
                    msg = 'Error: session key is invalid'
                    self.send_response_only(400, msg)
            logging.info(msg)
            self.send_header('Connection', 'close')
            self.end_headers()

        elif self.path == '/vault_space':
            # отримуємо ключ сесії
            session_key = self.headers.get('Cookie')
            # перевіряємо чи ключ сесії був переданий
            if session_key == None or session_key == '':
                msg = 'Error: You must login first.'
                self.send_response_only(400, msg)
            else:
                # перевіряємо чи дійсна сесія
                if self.server.session.all_sessions.get(session_key):
                    # оновлюємо час останньої активності
                    self.server.session.update(session_key)
                    # визначаємо ім'я користувача по ключу сесії
                    username = self.server.session.all_sessions[session_key]['user']
                    # визначаємо директорію користувача
                    user_dir = os.path.join(STORAGE_PATH, username)
                    # визначаємо всі файли, які лежать в директорії користувача
                    user_files = os.listdir(user_dir)
                    size_files = 0
                    # визначаємо загальний розмір файлів користувача
                    for file in user_files:
                        size_files += os.path.getsize(os.path.join(STORAGE_PATH, username, file))
                    # форматуємо вивід
                    if size_files / 10 ** 9 > 1:
                        size_files_format = str(round(size_files / 10 ** 6, 3)) + ' GB'
                    elif size_files / 10 ** 6 > 1:
                        size_files_format = str(round(size_files / 10 ** 6, 3)) + ' MB'
                    else:
                        size_files_format = str(round(size_files / 10 ** 3, 3)) + ' kB'
                    msg = '{size_files} / {max_disk_volume} GB'.format(size_files=size_files_format, max_disk_volume=MAX_DISK_SPACE_SIZE / 10 ** 9)
                    self.send_response_only(200, msg)
                    msg = 'User "{user}": command <{command}> done successfully.'.format(user=username,
                                                                                         command=self.path)
                else:
                    msg = 'Error: session key is invalid'
                    self.send_response_only(400, msg)
            logging.info(msg)
            self.send_header('Connection', 'close')
            self.end_headers()

    def do_POST(self):
        logging.info('New command <{command}> from client {address}'.format(command=self.path, address=self.address_string()))
        content_length = int(self.headers['Content-Length'])
        file_content = self.rfile.read(content_length)
        if self.path == '/connect':
            data = json.loads(file_content)
            username = data['username'].capitalize()
            password = data['password']
            msg = client_commands.connect(username, password)
            # якщо виникла помилка - повідомляємо клієнта
            if msg[0:5] == 'Error':
                logging.info(msg)
                print(msg)
                self.send_response_only(400, msg)
            # інакше - перевірямо пароль
            else:
                # отримуємо сіль
                salt = msg[32:]
                if msg == verify_password(password, salt):
                    msg = 'User "{user}" successfully authorized.'.format(user=username)
                    logging.info(msg)
                    print(msg)
                    # Створюємо сесію для цього користувача
                    session_key = self.server.session.create(username)
                    self.send_response(200, msg)
                    self.send_header('Set-Cookie', '{}'.format(session_key))
                else:
                    msg = 'Error: password of user "{user}" is incorrect.'.format(user=username)
                    logging.info(msg)
                    print(msg)
                    self.send_response_only(400, msg)
            self.send_header('Connection', 'close')
            self.end_headers()

        elif self.path == '/size':
            data = json.loads(file_content)
            file_name = data['file_name']
            # отримуємо ключ сесії
            session_key = self.headers.get('Cookie')
            # перевіряємо чи ключ сесії був переданий
            if session_key == None or session_key == '':
                msg = 'Error: You must login first.'
                self.send_response_only(400, msg)
            else:
                # перевіряємо чи дійсна сесія
                if self.server.session.all_sessions.get(session_key):
                    # оновлюємо час останньої активності
                    self.server.session.update(session_key)
                    # визначаємо ім'я користувача по ключу сесії
                    username = self.server.session.all_sessions[session_key]['user']
                    file_path = os.path.join(STORAGE_PATH, username, file_name)
                    # перевіряємо чи файл існує
                    if os.path.exists(file_path):
                        # визначаємо розмір файла користувача
                        size_file = os.path.getsize(file_path)

                        # форматуємо вивід
                        if size_file / 10 ** 9 > 1:
                            size_file_format = str(round(size_file / 10 ** 6, 3)) + ' GB'
                        elif size_file / 10 ** 6 > 1:
                            size_file_format = str(round(size_file / 10 ** 6, 3)) + ' MB'
                        else:
                            size_file_format = str(round(size_file / 10 ** 3, 3)) + ' kB'
                        msg = 'Size of file "{file}" is {size}.'.format(file=file_name, size=size_file_format)
                        self.send_response_only(200, msg)
                        msg = 'User "{user}": command <{command}> done successfully.'.format(user=username,
                                                                                             command=self.path)
                    else:
                        msg = 'Error: the file "{file}" does not exist. '.format(file=file_name)
                        self.send_response_only(400, msg)
                else:
                    msg = 'Error: session key is invalid'
                    self.send_response_only(400, msg)
            logging.info(msg)
            self.send_header('Connection', 'close')
            self.end_headers()

        elif self.path == '/delete':
            data = json.loads(file_content)
            file_name = data['file_name']
            # отримуємо ключ сесії
            session_key = self.headers.get('Cookie')
            # перевіряємо чи ключ сесії був переданий
            if session_key == None or session_key == '':
                msg = 'Error: You must login first.'
                self.send_response_only(400, msg)
            else:
                # перевіряємо чи дійсна сесія
                if self.server.session.all_sessions.get(session_key):
                    # оновлюємо час останньої активності
                    self.server.session.update(session_key)
                    # визначаємо ім'я користувача по ключу сесії
                    username = self.server.session.all_sessions[session_key]['user']
                    file_path = os.path.join(STORAGE_PATH, username, file_name)
                    # перевіряємо чи файл існує
                    if os.path.exists(file_path):
                        # визначаємо розмір файла користувача
                        os.remove(file_path)
                        msg = 'The file "{file}" is successfully deleted.'.format(file=file_name)
                        self.send_response_only(200, msg)
                        msg = 'User "{user}": command <{command}> done successfully.'.format(user=username,
                                                                                             command=self.path)
                    else:
                        msg = 'Error: the file "{file}" does not exist. '.format(file=file_name)
                        self.send_response_only(400, msg)
                else:
                    msg = 'Error: session key is invalid'
                    self.send_response_only(400, msg)
            logging.info(msg)
            self.send_header('Connection', 'close')
            self.end_headers()

        elif self.path == '/upload':
            data = json.loads(file_content)
            file_path = data['file_path']
            file_size = data['file_size']
            checksum = data['checksum']
            # отримуємо ключ сесії
            session_key = self.headers.get('Cookie')
            # перевіряємо чи ключ сесії був переданий
            if session_key == None or session_key == '':
                msg = 'Error: You must login first.'
                self.send_response(400, msg)
                self.send_header('Connection', 'close')
                self.end_headers()
            else:
                # перевіряємо чи дійсна сесія
                if self.server.session.all_sessions.get(session_key):
                    # оновлюємо час останньої активності
                    self.server.session.update(session_key)
                    # визначаємо ім'я користувача по ключу сесії
                    username = self.server.session.all_sessions[session_key]['user']

                    # перевіряємо чи вистачить місця для файлу користувача
                    user_files = os.listdir(os.path.join(STORAGE_PATH, username))
                    size_files = 0
                    # визначаємо загальний розмір файлів користувача
                    for file in user_files:
                        size_files += os.path.getsize(os.path.join(STORAGE_PATH, username, file))

                    if MAX_DISK_SPACE_SIZE < size_files + file_size:
                        msg = 'Error: File deleted. Not enough free disk space.'
                        self.send_response(400, msg)
                        self.send_header('Connection', 'close')
                        self.end_headers()
                    # перевіряємо чи розмір файла не більший допустимого
                    elif file_size <= MAX_FILE_SIZE:
                        # визначаємо ім'я файла
                        file_name = os.path.basename(file_path)
                        # визначаємо де файл буде зберігатися на сервері
                        file_path = os.path.join(STORAGE_PATH, username, file_name)
                        file = open(file_path, 'wb')
                        # повідомляємо клієнта, що починаємо завантаження файлу
                        self.send_response(200, 'OK')
                        self.send_header('Content-Length', file_size)
                        self.end_headers()

                        # починаємо завантажувати файл
                        amount_packet = int(file_size / 4096) + 1
                        MAX_AMOUNT_PACKET_FILE = int(MAX_FILE_SIZE / 4096) + 1
                        i = 0
                        while amount_packet - i:
                            data = self.rfile.read(4096)
                            i += 1
                            file.write(data)
                            # якщо реальний розмір файлу бульший за декларованого, то зупиняємо загрузку
                            if MAX_AMOUNT_PACKET_FILE < i:
                                break
                        file.close()
                        self.rfile.read()
                        # перевіряємо чи завантажили цілий файл
                        if checksum == get_checksum(file_path):
                            msg = 'File "{file}" is successfully uploaded.'.format(file=file_name)
                        else:
                            os.remove(file_path)
                            msg = 'Error: file is not uploaded. Wrong checksum.'
                        # перевіряємо чи не перевищений ліміт сховища
                        size_files = 0
                        # визначаємо загальний розмір файлів користувача
                        for file in user_files:
                            size_files += os.path.getsize(os.path.join(STORAGE_PATH, username, file))
                        if size_files > MAX_DISK_SPACE_SIZE:
                            os.remove(file_path)
                            msg = 'Error: File deleted. Not enough free disk space.'

                    # інакше повідомляємо клієнта, що розмір файлу більший допустимого
                    else:
                        msg = 'Error: size of file is larger than allowed.'
                        self.send_response(400, msg)
                        self.send_header('Connection', 'close')
                        self.end_headers()
                else:
                    msg = 'Error: session key is invalid'
                    self.send_response(400, msg)
                    self.send_header('Connection', 'close')
                    self.end_headers()
            logging.info(msg)

        elif self.path == '/download':
            data = json.loads(file_content)
            file_name = data['file_name']
            # отримуємо ключ сесії
            session_key = self.headers.get('Cookie')
            # перевіряємо чи ключ сесії був переданий
            if session_key == None or session_key == '':
                msg = 'Error: You must login first.'
                self.send_response(400, msg)
                self.send_header('Connection', 'close')
                self.end_headers()
            else:
                # перевіряємо чи дійсна сесія
                if self.server.session.all_sessions.get(session_key):
                    # оновлюємо час останньої активності
                    self.server.session.update(session_key)
                    # визначаємо ім'я користувача по ключу сесії
                    username = self.server.session.all_sessions[session_key]['user']
                    file_path = os.path.join(STORAGE_PATH, username, file_name)
                    # перевіряємо чи файл існує
                    if os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                        self.send_response(200, 'OK')
                        self.send_header('Content-Length', file_size)
                        self.end_headers()
                        file = open(file_path, 'rb')
                        amount_packet = int(file_size / 4096) + 1
                        i = 0
                        while amount_packet - i:
                            content = file.read(4096)
                            self.wfile.write(content)
                            i += 1
                        file.close()
                        msg = 'File "{file}" is successfully uploaded.'.format(file=file_path)
                    else:
                        msg = 'Error: the file "{file}" does not exist. '.format(file=file_path)
                        self.send_response(400, msg)
                        self.end_headers()
                else:
                    msg = 'Error: session key is invalid'
                    self.send_response(400, msg)
                    self.end_headers()
            logging.info(msg)


def hash_password(password):
    h = hashlib.md5()
    salt = uuid.uuid4().hex
    h.update(bytes(password, 'utf8'))
    password = h.hexdigest()
    h = hashlib.md5()
    for i in range(3):
        h.update(bytes(password + salt, 'utf8'))
    return h.hexdigest() + salt


def verify_password(password, salt):
    h = hashlib.md5()
    for i in range(3):
        h.update(bytes(password + salt, 'utf8'))
    return h.hexdigest() + salt


def get_checksum(file_path):
    h = hashlib.md5()
    with open(file_path, 'rb') as f:
        content = f.read()
        h.update(content)
    return h.hexdigest()


if __name__ == '__main__':
    # set format of logs
    logging.basicConfig(filename="server.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")
    logging.info('Start server.')
    logging.info('Open the config file.')

    with open('server.conf', 'r') as f:
        HOST = f.readline().split('=')[1].strip()
        try:
            PORT = int(f.readline().split('=')[1])
            MAX_FILE_SIZE = int(f.readline().split('=')[1]) * 10 ** 6
            MAX_DISK_SPACE_SIZE = int(f.readline().split('=')[1]) * 10 ** 6
        except ValueError:
            msg = 'Incorrect config data. Value must be integer.'
            logging.info(msg)
            print(msg)
            exit(0)
        FILE_DB = f.readline().split('=')[1].strip()
        STORAGE_PATH = f.readline().split('=')[1].strip()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower().strip()
        if command == 'user-add':
            msg = 'New command <{}>.'.format(command)
            logging.info(msg)
            print(msg)
            username = sys.argv[2].capitalize().strip()
            password = sys.argv[3]
            # hashing password
            password = hash_password(password)
            msg = server_commands.user_add(username, password)
            logging.info(msg)
            print(msg)
            msg = 'Close the program.'
            logging.info(msg)
            print(msg)
            exit(0)
        elif command == 'user-del':
            msg = 'New command <{}>.'.format(command)
            logging.info(msg)
            print(msg)
            username = sys.argv[2].capitalize().strip()
            msg = server_commands.del_user(username)
            logging.info(msg)
            print(msg)
            msg = 'Close the program.'
            logging.info(msg)
            print(msg)
            exit(0)
        else:
            msg = 'Unknown command <{}>.'.format(command)
            logging.info(msg)
            print(msg)
            msg = 'Close the program.'
            logging.info(msg)
            print(msg)
            exit(0)

    server = MyHTTPServer((HOST, PORT), ChunkedHTTPRequestHandler)
    server.socket = ssl.wrap_socket(server.socket, keyfile='./cer/localhost.key', certfile='./cer/localhost.crt', server_side=True)
    # запускаємо поток для перевірки чи не закінчився термін дії сесії
    server.session.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.socket.close()
