from tornado import gen
import socket
import tornado.iostream
from tornado.escape import utf8, native_str
import base64
import functools
from tornado.util import b
from tornado.httputil import HTTPHeaders
import Cookie
import logging
import urlparse
import re
import json
import pdb

class Response(object):
    def __init__(self, data, stream):
        data = native_str(data.decode("latin1"))
        logging.info('got response headers %s' % data)
        first_line, _, header_data = data.partition("\n")
        match = re.match("HTTP/1.[01] ([0-9]+)", first_line)
        assert match
        self.code = int(match.group(1))
        self.headers = HTTPHeaders.parse(header_data)
        self.stream = stream
        self.data = None
        self.content_length = int(self.headers["Content-Length"])

    @gen.engine
    def read_body(self, callback=None):
        already_read = sum( map( len, self.stream._read_buffer ) )
        toread = self.content_length - already_read
        assert toread >= 0
        if toread == 0:
            self.body = self.stream._consume(already_read)
        else:
            self.body = yield gen.Task(self.stream.read_bytes, self.content_length)

        if self.code == 200:
            try:
                self.data = json.loads(self.body)
            except:
                self.data = None
        self.stream._current_request = None
        callback()
        

class Request(object):
    def __init__(self, uri, method='GET', headers=None, body=None):
        self.method = method
        self.uri = uri
        self.headers = headers
        self.body = body

    def generate_headers(self):
        request_lines = [utf8("%s %s HTTP/1.1" % (self.method,
                                                  self.uri))]
        for k, v in self.headers.items():
            line = utf8(k) + b(": ") + utf8(v)
            request_lines.append(line)
        toreturn = b("\r\n").join(request_lines) + b("\r\n\r\n")
        return toreturn


class BTServer(object):

    def __init__(self, host, port, username, password, token_auth = True):
        logging.info('initialize btserver on %s:%s, %s:%s' % (host,port,username,password))
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.token_auth = token_auth
        self.address = '%s:%s' % (self.host, self.port)
        self.streams = {}

        self.token = None
        self.GUID = None
    
    def on_close(self, stream):
        logging.warn('%s %s connection close' % (self, stream))

    @gen.engine
    def get_stream(self, callback=None):
        found = False
        for stream,v in self.streams.iteritems():
            if not stream._connecting and not stream._current_request and not stream.closed():
                found = True
                callback(stream)
                break
        if not found:
            stream = yield gen.Task( self.create_stream )
            callback(stream)

    @gen.engine
    def create_stream(self, callback):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        stream = tornado.iostream.IOStream(s)
        stream._current_request = None
        stream.set_close_callback(functools.partial(self.on_close, stream))
        yield gen.Task( stream.connect, (self.host, self.port) )
        self.streams[ stream ] = None
        callback(stream)

    @gen.engine
    def do_request(self, request, callback=None):
        logging.info('gettin stream')
        stream = yield gen.Task( self.get_stream )
        logging.info('got stream %s' % stream)
        logging.info('writing request: %s' % request.generate_headers())
        stream._current_request = request
        stream.write( request.generate_headers() )
        data = yield gen.Task( stream.read_until, b("\r\n\r\n") )
        response = Response( data, stream )
        yield gen.Task( response.read_body )
        callback(response)

    def create_request(self, uri):
        headers = { 'Authorization': 'Basic %s' % base64.b64encode('%s:%s' % (self.username, self.password)) }
        if self.token and uri != '/gui/token.html':
            if urlparse.urlparse(uri).query:
                uri += '&token=%s' % self.token
            else:
                uri += '?token=%s' % self.token
            if self.GUID:
                headers['Cookie'] = 'GUID=%s' % self.GUID
        request = Request(uri, headers = headers)
        return request

    @gen.engine
    def get(self, uri, callback=None):
        if self.token_auth and not self.token:
            yield gen.Task( self.get_token )
        logging.info('get %s' % uri)
        request = self.create_request(uri)
        result = yield gen.Task(self.do_request, request)
        callback(result)
        
    @gen.engine
    def get_token(self, callback=None):
        request = self.create_request('/gui/token.html')
        result = yield gen.Task( self.do_request, request )
        if 'Set-Cookie' in result.headers:
            self.GUID = Cookie.BaseCookie(result.headers['Set-Cookie']).values()[0].value
        begstr = "style='display:none;'>"
        endstr = "</div>"
        i1 = result.body.index(begstr)
        i2 = result.body.index(endstr)
        self.token = result.body[i1+len(begstr):i2]
        callback()
