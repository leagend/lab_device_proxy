#!/usr/bin/env python2.7
# PLEASE LEAVE THE SHEBANG: the proxy client runs as a standalone Python file.

# Google BSD license http://code.google.com/google_bsd_license.html
# Copyright 2014 Google Inc. wrightt@google.com

"""A proxy to run adb and idevice* commands for a remote lab Android/iOS device.

Forwards the commands to a proxy server that runs them on its machine.
"""

# Only Python built-in imports! Runs as a standalone Python file.
import cStringIO as StringIO
import httplib
import os
import os.path
import platform
import signal
import sys
import urlparse

import yaml

from lab_common import PARSER, ChunkHeader, ReadExactly, GetStack, Untar, MAX_READ, \
    OutputFileParameter

LAB_DEVICE_PROXY_URL = 'LAB_DEVICE_PROXY_URL'


def main(args):
    """Runs the client, exits when done.

    See _CreateParser for the complete list of supported commands.

    Requires a $LAB_DEVICE_PROXY_URL environment variable (or --url argument)
    that's set to the server's URL.

    Args:
      args: List of command and arguments, e.g.
          ['./adb', 'install', 'foo.apk']
        In the expected environment, symlinks or copies of this Python file are
        created for every command:
          adb, idevice_id, ideviceinfo, ...
        so arg[0] is the command name.

        If arg[0] contains "lab_device_proxy_client", it is skipped, along with
        optional "--url URL" arguments.  This helps support unit tests and
        callers who don't want to create symlinks and/or set the
        "$LAB_DEVICE_PROXY_URL" environment variable.  E.g.:
          ['lab_device_proxy_client.py', '--url', 'http://x:8084', 'ideviceinfo']
        is equivalent to:
          os.environ['LAB_DEVICE_PROXY_URL'] = 'http://x:80804'
          ['ideviceinfo'].
    """
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # Exit on Ctrl-C

    args = list(args)

    # Make stdout and stderr unbuffered, so we could get the output
    # immediately when we redirect the output to another stream.
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

    url = os.environ.get(LAB_DEVICE_PROXY_URL)

    if 'lab_device_proxy_client' in args[0]:
        args.pop(0)  # happens when there are no symlinks.
        if len(args) > 1 and args[0] == '--url':
            args.pop(0)
            url = args.pop(0)

    if args:
        args[0] = os.path.basename(args[0])

    if not url:
        servers_conf = os.path.join(os.path.dirname(__file__), 'servers.yml')
        if os.path.isfile(servers_conf):
            servers = yaml.load(open(servers_conf))['servers']
            server_lists = []
            for server in servers['android']:
                params = PARSER.parse_args(['adb', 'devices'])
                print("Android Devices on {0}:".format(server))
                if not call_proxy_client('http://{0}:8084'.format(server), params):
                    server_lists.append(server)
            for server in servers['ios']:
                params = PARSER.parse_args(['idevice_id', '-l'])
                print("IOS Devices on {0}:".format(server))
                if not call_proxy_client('http://{0}:8084'.format(server), params):
                    server_lists.append(server)
                    print("\n")
            if len(server_lists) > 1:
                while True:
                    server_input = raw_input(
                        "Please input the HOST IP you are going to execute the command line from the following list: "
                        "\n{0}\n>>> HOST IP: ".format("\n".join(server_lists))).strip()
                    if server_input in server_lists:
                        url = 'http://{0}:8084'.format(server_input)
                        break
                    print("\n\nThe IP you input did not match one of the list above. Please try again!\n")
            elif len(server_lists) == 1:
                url = 'http://{0}:8084'.format(server_lists[0])
            else:
                sys.exit('No valid device server found!')
            if platform.system() == 'Windows':
                os.system('echo set {0}={1} > set_url.bat'.format(LAB_DEVICE_PROXY_URL, url))
                print("To avoid select IP, you're suggested to run \"set_url.bat\" before next execution!")
            else:
                os.system('echo export {0}={1} > set_url.sh'.format(LAB_DEVICE_PROXY_URL, url))
                print("To avoid select IP, you're suggested to run \"source set_url.sh\" before next execution!")
            print("\n")
        else:
            sys.exit(
                'The lab device proxy server URL is not set.\n\n'
                'Either set the environment variable, e.g.:\n'
                '  export LAB_DEVICE_PROXY_URL=http://mylab:8084\n'
                'or invoke the proxy with a "--url" argument, e.g.:\n'
                '  lab_device_proxy_client.py --url http://mylab:8084 %s ...' %
                (args[0] if args else ''))

    try:
        params = PARSER.parse_args(args)
        resemble_adb_shell(params)
    except ValueError:
        sys.exit(1)
        pass
    # print(args)
    # print(params)
    exit_code = call_proxy_client(url, params)
    sys.exit(exit_code)


def resemble_adb_shell(params):
    if params[0].value == 'adb' and params[-1].value == 'shell' and params[2].value == '-s':
        param_len = len(params)
        last_index = param_len - 2
        _tmp_params = []
        _tmp_params.append(params[1])
        _tmp_params.extend(params[4:last_index + 1])
        while last_index > 3:
            params.pop(last_index)
            last_index -= 1
        params.pop(1)
        params.extend(_tmp_params)
        i = 0
        while i < len(params):
            params[i].index = i
            i += 1


def call_proxy_client(url, params):
    # TODO(user) support os.environ.get('ANDROID_SERIAL')?
    exit_code = 1
    # print(url, params)
    try:
        client = LabDeviceProxyClient(url, sys.stdout, sys.stderr)
        exit_code = client.Call(*params)
    except:  # pylint: disable=bare-except
        sys.stderr.write(GetStack())
    return exit_code


class LabDeviceProxyClient(object):
    """The Proxy Client."""

    def __init__(self, url, stdout, stderr):
        self._url = (url if '://' in url else ('http://%s' % url))
        self._stdout = stdout
        self._stderr = stderr

    def Call(self, *params):
        """Calls the proxy.

        Args:
          *params: A vararg array of Parameters.
        Returns:
          The exit code
        """
        connection = _LabHTTPConnection(urlparse.urlsplit(self._url).netloc)
        try:
            self._SendRequest(params, connection)
            return self._ReadResponse(params, connection)
        finally:
            connection.close()

    def _SendRequest(self, params, connection):
        """Sends a command to an HTTPConnection, chunk-encoded.

        Args:
          params: List of Parameters.
          connection: HTTPConnection.
        """
        connection.putrequest('POST', ''.join(urlparse.urlsplit(self._url)[2:]))
        connection.putheader('Content-Type', 'text/plain; charset=utf=8')
        connection.putheader('Transfer-Encoding', 'chunked')
        connection.putheader('Content-Encoding', 'UTF-8')
        connection.endheaders()
        for param in params:
            param.SendTo(connection)
        connection.send('0\r\n\r\n')

    def _ReadResponse(self, params, connection):
        """Reads the response chunks from the server.

        Args:
          params: a sequence of command line arguments.
          connection: an HTTPConnection.
        Returns:
          int exitcode
        Raises:
          RuntimeError: if the server rejected the request.
          ValueError: if the response is invalid.
        """
        # Check status
        response = connection.getresponse()
        if response.status != httplib.OK:
            raise RuntimeError('Request failed: %s %s' % (
                response.status, response.reason))
        if response.getheader('Transfer-Encoding') != 'chunked':
            raise RuntimeError('Invalid response headers: %s' % response.msg)
        from_stream = response

        # Map chunk "id" to writable file_pointer ("fp").
        id_to_fp = {}
        id_to_fp['1'] = self._stdout
        id_to_fp['2'] = self._stderr
        id_to_fp['exit'] = StringIO.StringIO()

        # Map chunk "id" to output file_name ("fn").
        id_to_fn = {}
        for index, param in enumerate(params):
            if isinstance(param, OutputFileParameter):
                id_to_fn['o%d' % index] = param.value

        # Read chunks
        try:
            while True:
                header = ChunkHeader()
                header.Parse(from_stream.readline())
                if header.len_ <= 0:
                    break
                handler_id = header.id_
                fp = id_to_fp.get(handler_id)
                if not fp and handler_id not in id_to_fn:
                    raise ValueError('Unknown output stream id: %s' % header)
                if header.is_absent_ or header.is_empty_:
                    ReadExactly(from_stream, header.len_)
                else:
                    if not fp:
                        fn = id_to_fn[handler_id]
                        # This fn path is from our caller, not the server, so we trust it
                        if header.is_tar_:
                            fp = Untar(fn)
                        elif os.path.isfile(fn) or not os.path.exists(fn):
                            fp = open(fn, 'wb')
                        else:
                            raise ValueError('Expecting a tar, not %s' % header)
                        id_to_fp[handler_id] = fp
                    bytes_read = 0
                    while bytes_read < header.len_:
                        data = from_stream.read(min(MAX_READ, header.len_ - bytes_read))
                        bytes_read += len(data)
                        fp.write(data)
                if ReadExactly(from_stream, 2) != '\r\n':
                    raise ValueError('Chunk does not end with crlf')
        finally:
            for handler_id in id_to_fn:
                if handler_id in id_to_fp:
                    id_to_fp[handler_id].close()

        errcode_stream = id_to_fp['exit']
        return int(errcode_stream.getvalue()) if errcode_stream.tell() else None


class _LabHTTPResponse(httplib.HTTPResponse):
    """Provides _ReadResponse access to the underlying reader stream."""

    def readline(self):  # pylint: disable=g-bad-name
        return self.fp.readline()

    def _read_chunked(self, amt):  # pylint: disable=g-bad-name
        """Disable the default chunk-reader and simply return the data."""
        return self.fp._sock.recv(amt)  # pylint: disable=protected-access


class _LabHTTPConnection(httplib.HTTPConnection):
    response_class = _LabHTTPResponse


#
# THE REST IS SHARED CLIENT & SERVER CODE
#
# This will stay here, since we want the client to be a self-contained .py file.
#


# Must be defined after _CreateParser().
#
# We could define this at the top of our file, but only if we wrap it to defer
# the eval to first use, e.g.:
#   PARSER = LazyProxy(lambda: _CreateParser())  # intercept __getattribute__
# but that's more confusing than it's worth.


if __name__ == '__main__':
    main(sys.argv)
