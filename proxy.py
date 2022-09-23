#!/usr/bin/python3

from argparse import ArgumentParser
import concurrent.futures
import os
import signal
import socket
import sys

"""Class for parsing and representing a Uniform Resource Indicator (URI)"""
class URI:
    """Create and parse a URI"""
    def __init__(self, string):
        self._uri = string

        # Parse URI
        self._absolute = string.startswith('http://')
        string = string[7:] if self._absolute else string
        abs_path_start = string.find('/')
        if abs_path_start == -1:
            self._host = string
            self._abs_path = '/'
        elif abs_path_start == 0:
            self._host = None
            self._port = None
            self._abs_path = string
        else:
            self._host = string[:abs_path_start]
            self._abs_path = string[abs_path_start:]
        if self._host is not None:
            port_start = self._host.find(':')
            if port_start == -1:
                self._port = 80
            else:
                self._port = int(self._host[port_start+1:])
                self._host = self._host[:port_start]
    
    """Get the full URI"""
    @property
    def uri(self):
        return self._uri

    """Determine whether the URI is absolute (True) or relative (False)"""
    @property
    def absolute(self):
        return self._absolute

    """Get the host from the URI; returns None if the URI is relative"""
    @property
    def host(self):
        return self._host

    """Get the port from the URI; returns None if the URI is relative; returns
    80 if the URI is absolute and no port was specified"""
    @property
    def port(self):
        return self._port

    """Get the path from the URI"""
    @property
    def abs_path(self):
        return self._abs_path

    """Get a string representation of the URI"""
    def __str__(self):
        return self._uri

"""Class for parsing and representing a HTTP request"""
class HTTPRequest:
    """Create a HTTP request"""
    def __init__(self, method, uri, version='HTTP/1.1', headers={}, body=None):
        self._method = method
        self._uri = uri
        self._version = version
        self._headers = headers
        self._body = body
    
    """Get the method from the HTTP request"""
    @property
    def method(self):
        return self._method

    """Get the URI from the HTTP request; returns a URI object"""
    @property
    def uri(self):
        return self._uri

    """Set the URI in the HTTP request"""
    def set_uri(self, uri):
        if type(uri) is str:
            self._uri = URI(uri)
        elif type(uri) is URI:
            self._uri = uri
        else:
            raise ValueError('Must provide a string or URI object')

    """Get the version from the HTTP response"""
    @property
    def version(self):
        return self._version

    """Get the headers from the HTTP request; returns a dictionary of 
    field-name, field-value pairs"""
    @property
    def headers(self):
        return self._headers

    """Set the value for a specific header field"""
    def set_header(self, name, value):
        self._headers[name] = value

    """Remove a specific header field from the HTTP request"""
    def remove_header(self, name):
        if name in self._headers:
            del self._headers[name]

    """Get the body (i.e., data) from the HTTP request; returns None if there 
    is no data"""
    @property
    def body(self):
        return self._body

    """Create a new HTTPRequest object by parsing a string containing an HTTP 
    request"""
    @classmethod
    def parse(cls, string):
        # Split into lines
        lines = string.split('\r\n')
        if len(lines) < 3:
            raise ValueError('HTTP request must contain at least a request-line and a blank line')

        # Find blank line
        blank_index = -1
        for i, line in enumerate(lines): 
            if lines[i] == '':
                blank_index = i
                break
        if blank_index == -1:
            raise ValueError('HTTP response must contain a blank line before the message-body')

        # Parse request line
        request_line = lines[0].split(' ')
        if len(request_line) != 3:
            raise ValueError('HTTP request-line must contain a method, request-URI, and HTTP-version separated by spaces')
        method = request_line[0]
        uri = URI(request_line[1])
        version = request_line[2]
        
        # Parse message-header(s)
        headers = {} 
        for line in lines[1:blank_index]:
            colon_index = line.find(':')
            if colon_index == -1:
                raise ValueError('HTTP message-header must contain a field-name and a field-value separated by a colon (:)')
            headers[line[:colon_index]] = line[colon_index+1:].strip()

        # Body is remainder of message
        body = lines[blank_index+1:]
        if len(body) == 0:
            body = None
        else:
            body = '\r\n'.join(body)

        return HTTPRequest(method, uri, version, headers, body)

    """Convert an HTTPRequest object into a string that is a properly formatted
    HTTP request"""
    def deparse(self):
        # TODO
        # Request Line
        req = '' + self.method + ' ' + str(self.uri) + ' ' + self.version + '\r\n'
        # Headers
        for key in self.headers:
            req += key + ': ' + self.headers[key] + '\r\n'
        req += '\r\n'
        return req                  # return request string

    """Create an exact copy of the HTTP request; returns an HTTPRequest 
    object"""
    def clone(self):
        return HTTPRequest(self._method, self._uri, self._version, 
                self._headers, self._body)

    """Get a string representation of the HTTP request; note, this string does
    not conform to the format specified for HTTP requests sent across a network;
    use the deparse method to obtain such a representation of the request"""
    def __str__(self):
        return '\n'.join([
                'Method: ' + self._method,
                'URI: ' + str(self._uri),
                'Version: ' + self._version,
                'Headers:\n' + '\n'.join(['\t' + name + ': ' + value 
                        for name, value in self._headers.items()]),
                'Body:\n' + self._body
                ])

"""Class for parsing and representing a HTTP response"""
class HTTPResponse:
    def __init__(self, status_code, reason_phrase, version='HTTP/1.1', 
            headers={}, body=None):
        self._status_code = status_code
        self._reason_phrase = reason_phrase
        self._version = version
        self._headers = headers
        self._body = body

    """Get the status code from the HTTP response"""
    @property
    def status_code(self):
        return self._status_code

    """Get the reason phrase from the HTTP response"""
    @property
    def reason_phrase(self):
        return self._reason_phrase

    """Get the version from the HTTP response"""
    @property
    def version(self):
        return self._version

    """Get the headers from the HTTP response; returns a dictionary of 
    field-name, field-value pairs"""
    @property
    def headers(self):
        return self._headers

    """Set the value for a specific header field"""
    def set_header(self, name, value):
        self._headers[name] = value

    """Remove a specific header field from the HTTP response"""
    def remove_header(self, name):
        if name in self._headers:
            del self._headers[name]

    """Get the body (i.e., data) from the HTTP response; returns None if there 
    is no data"""
    @property
    def body(self):
        return self._body

    """Create a new HTTPResponse object by parsing a string containing an HTTP 
    response"""
    @classmethod
    def parse(cls, string):
        # Split into lines
        lines = string.split('\r\n')
        if len(lines) < 3:
            raise ValueError('HTTP response must contain at least a status-line and a blank line')

        # Find blank line
        blank_index = -1
        for i, line in enumerate(lines): 
            if lines[i] == '':
                blank_index = i
                break
        if blank_index == -1:
            raise ValueError('HTTP response must contain a blank line before the message-body')

        # Parse status line
        status_line = lines[0].split(' ')
        if len(status_line) < 3:
            raise ValueError('HTTP status-line must contain a HTTP-version, status-code, and reason-phrase separated by spaces')
        version = status_line[0]
        status_code = int(status_line[1])
        reason_phrase = ' '.join(status_line[2:])
        
        # Parse message-header(s)
        headers = {} 
        for line in lines[1:blank_index]:
            colon_index = line.find(':')
            if colon_index == -1:
                raise ValueError('HTTP response-header must contain a field-name and a field-value separated by a colon (:)')
            headers[line[:colon_index]] = line[colon_index+1:].strip()

        # Body is remainder of message
        body = lines[blank_index+1:]
        if len(body) == 0:
            body = None
        else:
            body = '\r\n'.join(body)

        return HTTPResponse(status_code, reason_phrase, version, headers, body)

    """Convert an HTTPResponse object into a string that is a properly formatted
    HTTP response"""
    def deparse(self):
        # TODO
        # First line (for example, 'HTTP/1.1 200 OK\r\n')
        resp = '' + self.version + ' ' + str(self.status_code) + ' ' + self.reason_phrase + '\r\n\r\n'
        # Headers
        if bool(self.headers):
            for key in self.headers:
                resp += key + ': ' + self.headers[key] + '\r\n'
            resp += '\r\n'
        if bool(self.body):
            resp += self.body
        return resp

    """Create an exact copy of the HTTP response; returns an HTTPResponse 
    object"""
    def clone(self):
        return HTTPResponse(self._status_code, self._reason_phrase, 
                self._version, self._headers, self._body)

    """Get a string representation of the HTTP response; note, this string does
    not conform to the format specified for HTTP responses sent across a 
    network; use the deparse method to obtain such a represetnation of the 
    response"""
    def __str__(self):
        return '\n'.join([
                'Version: ' + self._version,
                'Status code: ' + str(self._status_code),
                'Reason phrase: ' + self._reason_phrase,
                'Headers:\n' + '\n'.join(['\t' + name + ': ' + value 
                        for name, value in self._headers.items()]),
                'Body:\n' + self._body
                ])

"""Main method"""
def main():
    # Parse arguments
    arg_parser = ArgumentParser(description='Messenger', add_help=False)
    arg_parser.add_argument('-p', '--port', dest='port', action='store',
            type=int, required=True, help='''Port to listen on''')
    arg_parser.add_argument('-t', '--threads', dest='max_threads',
            action='store', type=int, default=10, 
            help='''Maximum number of threads to spawn''')
    settings = arg_parser.parse_args()

    print('Proxy PID: %d' % os.getpid())

    # Gracefully shut down proxy when ctrl+c is pressed 
    def shutdown(sig, frame):
        print('Shutting down proxy')
        # Clean-up
        # TODO
        # Close client socket and proxy socket to shutdown proxy
        client_sock.close()
        psock.close()
        sys.exit(0)

    # Catch ctrl+c
    signal.signal(signal.SIGINT, shutdown)

    # Project 1 – 11 Feb 2022
    # Implement proxy
    # TODO
    # Create a server socket, listen and accept any incoming connections
    psock = socket.socket()             # proxy for receiving requests/responses
    psock_out = socket.socket()         # proxy for sending requests/responses
    psock.bind(('',settings.port))
    psock.listen()

    # Handle multiple clients via a pool of threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_threads) as executor:
        while (True):
            (client_sock, (client_host, client_port)) = psock.accept()
            executor.submit(handle_client, client_sock)     # submit task to thread


# 12 Feb 2022 – I added a client handler function that could parse client requests
def handle_client(sock):
    socket_to_remote = socket.socket()

    # Keep reading from client until '\r\n\r\n' is detected (blank line)
    req = sock.recv(4096).decode()
    while '\r\n\r\n' not in req:
        req += sock.recv(4096).decode()
    
    # Parse the HTTPRequest sent by client
    try:
        req_parsed = HTTPRequest.parse(req)          
    except Exception as e:
        # print(e)
        err = HTTPResponse.parse('HTTP/1.1 400 Bad Request\r\n\r\n').deparse()
        sock.send(err.encode())
        socket_to_remote.close()
        sock.close()
        return
    
    # Check if the URI sent from client was in absolute form
    if not req_parsed.uri.absolute:
        print()
        # 400 Bad Request Error (need to implement!)
        err = HTTPResponse.parse('HTTP/1.1 400 Bad Request\r\n\r\n').deparse()
        sock.send(err.encode())
        socket_to_remote.close()
        sock.close()
        return

    # Check if the HTTP Request has a method other than GET
    if req_parsed.method != 'GET':
        print()
        # 501 Not Implemented Error (need to implement!)
        err = HTTPResponse.parse('HTTP/1.1 501 Not Implemented\r\n\r\n').deparse()
        sock.send(err.encode())
        socket_to_remote.close()
        sock.close()
        return

    # Manipulate HTTP Request for it to be ready to be sent to remote server
    remote_server_host = req_parsed.uri.host
    remote_server_port = req_parsed.uri.port
    req_parsed.set_header('Host', req_parsed.uri.host)
    req_parsed.set_uri(req_parsed.uri.abs_path)
    req_parsed.remove_header('Accept-Encoding')         # remove Accept-Encoding header
    req_parsed.set_header('Connection', 'close')
    req_deparsed = req_parsed.deparse()
    # print(req_deparsed)

    # Send deparsed request to remote server
    try:
        socket_to_remote.connect((remote_server_host,remote_server_port))
    except:
        err = HTTPResponse.parse('HTTP/1.1 502 Bad Gateway\r\n\r\n').deparse()
        sock.send(err.encode())
        socket_to_remote.close()
        sock.close()
        return
    
    socket_to_remote.send(req_deparsed.encode())
    # Receive reply back from remote server
    resp = socket_to_remote.recv(4096).decode()
    # print(resp)

    # Relay it back to client
    sock.send(resp.encode())
    # Close both sockets
    socket_to_remote.close()
    sock.close()
    return

if __name__ == '__main__':
    main()
