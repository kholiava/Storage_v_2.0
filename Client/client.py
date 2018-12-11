import os
import sys
from http import client
import ssl
import json
import hashlib


def hash_password(password):
    h = hashlib.md5()
    h.update(bytes(password, 'utf8'))
    return h.hexdigest()


class Client:
    def __init__(self, server='localhost', port=8888):
        self.session_key = ''
        self.server = server
        try:
            self.port = int(port)
        except ValueError:
            print('Error: incorrect port.')
            exit(0)

    def connect(self, server, port, username, password):
        self.server = server
        try:
            self.port = int(port)
        except ValueError:
            print('Error: incorrect port.')
            exit(0)

        data = {
            'username': username,
            'password': hash_password(password)
        }
        data = json.dumps(data)

        ctx = ssl.SSLContext()
        ctx.load_verify_locations(capath='ca.cert.pem')
        connection = client.HTTPSConnection(host=self.server, port=self.port, context=ctx)
        headers = {
            'Content-Type': 'application/json',
            'Content-Length': len(data),
            'Accept': 'text/plain',
            'Accept-Encoding': 'gzip, deflate, br'}
        connection.request('POST', '/connect', body=data, headers=headers)
        response = connection.getresponse()
        print('Answer from server:', response.reason)
        if response.status == 200:
            self.session_key = response.getheader('Set-Cookie')
        connection.close()

    def list(self):
        ctx = ssl.SSLContext()
        ctx.load_verify_locations(capath='ca.cert.pem')
        connection = client.HTTPSConnection(host=self.server, port=self.port, context=ctx)
        headers = {
            'Cookie': '{}'.format(self.session_key)}
        connection.request('GET', '/list', headers=headers)
        response = connection.getresponse()
        print('Answer from server:', response.reason)
        connection.close()

    def upload(self, path):
        # спробуємо відкрити файл, якщо невдача, то повідомляємо про помилку
        try:
            file = open(path, 'rb')
        except IOError as err:
            print(str(err))
            return
        # створюємо ssl-зєднання з сервером
        ctx = ssl.SSLContext()
        ctx.load_verify_locations(capath='ca.cert.pem')
        connection = client.HTTPSConnection(host=self.server, port=self.port, context=ctx)
        file_size = os.path.getsize(path)
        # готуємо дані для відправки на сервер
        data = {
            'file_path': path,
            'file_size': file_size,
            'checksum': self.__get_checksum(path)
        }
        data = json.dumps(data)
        headers = {
            'Cookie': '{}'.format(self.session_key),
            'Content-Type': 'application/json',
            'Content-Length': len(data)
        }
        connection.request('POST', '/upload', body=data, headers=headers)

        # отримуємо відповідь сервера
        response = connection.getresponse()
        # якщо нема помилки, то починаємо вигрузку
        if response.status == 200:
            # розраховуємо кількість пакетів
            amount_packet = int(file_size / 4096) + 1
            i = 0
            while amount_packet - i:
                data = file.read(4096)
                try:
                    connection.send(data)
                except BrokenPipeError:
                    print('Connection closed by server.')
                    return
                else:
                    print('Uploading: {} %'.format(round(i / amount_packet * 100, 2)), end='\r')
                i += 1
            print('File is successfully uploaded.')
            file.close()
        # інакше повідомляємо про помилку
        else:
            print('Answer from server:', response.reason)
        connection.close()

    def download(self, file_name, path):
        ctx = ssl.SSLContext()
        ctx.load_verify_locations(capath='ca.cert.pem')
        connection = client.HTTPSConnection(host=self.server, port=self.port, context=ctx)
        file_size = os.path.getsize(path)
        data = {
            'file_name': file_name
        }
        data = json.dumps(data)
        headers = {
            'Cookie': '{}'.format(self.session_key),
            'Content-Type': 'application/json',
            'Content-Length': len(data)
        }
        try:
            connection.request('POST', '/download', body=data, headers=headers)
            response = connection.getresponse()
        except client.RemoteDisconnected:
            msg = 'Error: connection is closed by server.'
            print(msg)
            return

        # завантажуємо та зберігаємо файл
        if response.status == 200:
            file_size = int(response.getheader('Content-Length'))
            file_path = os.path.join(path, file_name)
            file = open(file_path, 'wb')
            amount_packet = int(file_size / 4096) + 1
            i = 0
            while amount_packet - i:
                content = response.read(4096)
                file.write(content)
                i += 1
                print('Downloading: {} %'.format(round(i / amount_packet * 100, 2)), end='\r')
            file.close()
            msg = 'File "{file}" is successfully downloaded.'.format(file=file_name)
            print(msg)
        else:
            print('Answer from server:', response.reason)

        connection.close()

    def delete(self, file_name):
        ctx = ssl.SSLContext()
        ctx.load_verify_locations(capath='ca.cert.pem')
        connection = client.HTTPSConnection(host=self.server, port=self.port, context=ctx)
        data = {
            'file_name': file_name
        }
        data = json.dumps(data)
        headers = {
            'Cookie': '{}'.format(self.session_key),
            'Content-Type': 'application/json',
            'Content-Length': len(data),
            'Accept': 'text/plain',
            'Accept-Encoding': 'gzip, deflate, br'}
        connection.request('POST', '/delete', body=data, headers=headers)
        response = connection.getresponse()
        print('Answer from server:', response.reason)
        connection.close()

    def size(self, file_name):
        ctx = ssl.SSLContext()
        ctx.load_verify_locations(capath='ca.cert.pem')
        connection = client.HTTPSConnection(host=self.server, port=self.port, context=ctx)
        data = {
            'file_name': file_name
        }
        data = json.dumps(data)
        headers = {
            'Cookie': '{}'.format(self.session_key),
            'Content-Type': 'application/json',
            'Content-Length': len(data),
            'Accept': 'text/plain',
            'Accept-Encoding': 'gzip, deflate, br'}
        connection.request('POST', '/size', body=data, headers=headers)
        response = connection.getresponse()
        print('Answer from server:', response.reason)
        connection.close()

    def vault_space(self):
        ctx = ssl.SSLContext()
        ctx.load_verify_locations(capath='ca.cert.pem')
        connection = client.HTTPSConnection(host=self.server, port=self.port, context=ctx)
        headers = {'Cookie': '{}'.format(self.session_key)}
        connection.request('GET', '/vault_space', headers=headers)
        response = connection.getresponse()
        print('Answer from server:', response.reason)
        connection.close()

    def __get_checksum(self, file_path):
        h = hashlib.md5()
        with open(file_path, 'rb') as f:
            content = f.read()
            h.update(content)
        return h.hexdigest()



c = Client()

