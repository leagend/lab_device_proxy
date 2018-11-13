#!/usr/bin/env python2.7
# PLEASE LEAVE THE SHEBANG: the proxy client runs as a standalone Python file.

# Google BSD license http://code.google.com/google_bsd_license.html
# Copyright 2014 Google Inc. wrightt@google.com

"""A proxy to run adb and idevice* commands for a remote lab Android/iOS device.

Forwards the commands to a proxy server that runs them on its machine.
"""

# Only Python built-in imports! Runs as a standalone Python file.
import argparse
import cStringIO as StringIO
import httplib
import os
import os.path
import platform
import re
import signal
import sys
import urlparse

import yaml

from lab_common import PARSER, ChunkHeader, SendChunk, ReadExactly, GetStack, SendTar, Untar

LAB_DEVICE_PROXY_URL = 'LAB_DEVICE_PROXY_URL'

MAX_READ = 8192


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
                print("Devices on {0}:".format(server))
                if not call_proxy_client('http://{0}:8084'.format(server), params):
                    server_lists.append(server)
            for server in servers['ios']:
                params = PARSER.parse_args(['idevice_id', '-l'])
                print("Devices on {0}:".format(server))
                if not call_proxy_client('http://{0}:8084'.format(server), params):
                    server_lists.append(server)
                    print("\n")
            if len(server_lists) > 1:
                while True:
                    server_input = raw_input("Please select the server IP from {0} which the dedicated device is connected to.\nServer IP: ".format(server_lists)).strip()
                    if server_input in server_lists:
                        url = 'http://{0}:8084'.format(server_input)
                        break
            elif len(server_lists) == 1:
                url = 'http://{0}:8084'.format(server_lists[0])
            else:
                sys.exit('No valid device server found!')
            if platform.system() == 'Windows':
                os.system('echo set {0}={1} > set_url.bat'.format(LAB_DEVICE_PROXY_URL, url))
                print("To avoid select IP, you're suggested to run \"set_url.bat\"un before next execution!")
            else:
                os.system('echo export {0}={1} > set_url.sh'.format(LAB_DEVICE_PROXY_URL, url))
                print("To avoid select IP, you're suggested to run \"source set_url.bat\" before next execution!")
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


class Parameter(object):
    """A command-line parameter."""

    def __init__(self, value):
        self.value = value
        # The argparser supports our custom parameters via "type=CLASSNAME", but it
        # only passes the value to the constructor.  So, our namespace sets the
        # "chunk_id" index after our constructor.
        self.index = None

    def SendTo(self, to_stream):
        """Sends this parameter as chunked input to the server.

        Args:
          to_stream: A socket.socket or a file object (e.g. StringIO buffer).
        """
        header = ChunkHeader('a%d' % self.index)
        SendChunk(header, str(self.value), to_stream)

    def __repr__(self):
        return str(self.value)


class AndroidSerialParameter(Parameter):
    """An Android Device ID."""

    def __init__(self, serial):
        super(AndroidSerialParameter, self).__init__(serial)
        if not re.match(r'\S+$', serial):
            raise ValueError('Invalid Android device id: %s' % serial)

    def __repr__(self):
        return '{serial}%s' % str(self.value)


class IOSDeviceIdParameter(Parameter):
    """An iOS Device ID."""

    def __init__(self, udid):
        super(IOSDeviceIdParameter, self).__init__(udid)
        if not re.match(r'[0-9a-f]{40}$', udid):
            raise ValueError('Invalid iOS device id: %s' % udid)

    def __repr__(self):
        return '{udid}%s' % str(self.value)


class InputFileParameter(Parameter):
    """An input file to upload to the server.

    The filename value is "input" relative to the remote server command, e.g.
    "adb install INPUT_APK".
    """

    def SendTo(self, to_stream):
        """Sends a chunked input file to the server.

        Args:
          to_stream: A socket.socket or a file object (e.g. StringIO buffer).
        """
        in_fn = self.value
        header = ChunkHeader('i%d' % self.index)
        header.in_ = os.path.basename(in_fn)
        if os.path.isfile(in_fn):
            # We could send this as a tar, as noted below.
            #   Pros: simplified code, preserves file attributes, compressed.
            #   Cons: server must support tars, added tar header/block data.
            with open(in_fn, 'r') as file_object:
                data = file_object.read(MAX_READ)
                if not data:
                    SendChunk(header, None, to_stream)
                else:
                    while data:
                        SendChunk(header, data, to_stream)
                        data = file_object.read(MAX_READ)
        elif os.path.exists(in_fn):
            header.is_tar_ = True
            SendTar(in_fn, os.path.basename(in_fn) + '/', header, to_stream)
        else:
            header.is_absent_ = True
            SendChunk(header, None, to_stream)

    def __repr__(self):
        return '{input_file}%s' % self.value


class OutputFileParameter(Parameter):
    """An output file that will be sent back from the server.

    The filename value is "output" relative to the remote server command, e.g.
    "adb pull foo OUTPUT_PATH".
    """

    def SendTo(self, to_stream):
        """Sends a chunked output-file placeholder to the server.

        Args:
          to_stream: A socket.socket or a file object (e.g. StringIO buffer).
        """
        out_fn = self.value
        header = ChunkHeader('o%d' % self.index)
        if os.path.isdir(out_fn):
            header.is_tar_ = True
            header.out_ = '.'
        else:
            # As noted in _SendInputFile, we could set is_tar_ here to force the
            # server to return a tar.  The same pros/cons apply.
            if not os.path.exists(out_fn):
                header.is_absent_ = True
            header.out_ = os.path.basename(out_fn)
        SendChunk(header, None, to_stream)

    def __repr__(self):
        return '{output_file}%s' % self.value


class ParameterNamespace(argparse.Namespace):
    """A modified argparse namespace that saves the parameter order."""

    def __init__(self, params=None):
        super(ParameterNamespace, self).__init__()
        self.params = (params if params is not None else [])

    def _Append(self, value):
        param = (value if isinstance(value, Parameter) else Parameter(value))
        param.index = len(self.params)
        self.params.append(param)

    def __setattr__(self, name, value):
        super(ParameterNamespace, self).__setattr__(name, value)
        if name and name[0] == '_':
            # Restore _l/__list back to -l/--list
            name = '-%s%s' % ('-' if name[1] == '_' else name[1], name[2:])
            self._Append(name)
        if isinstance(value, list):
            for v in value:
                self._Append(v)
        elif value and value is not True:
            self._Append(value)


class ParameterDecl(object):
    """A ParameterParser.AddParameter value."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class ParameterParser(object):
    """An argparse wrapper that saves the parameter order."""

    def __init__(self, prog, *decls, **kwargs):
        m = kwargs
        if 'add_help' not in m:
            m['add_help'] = False
        self.p = argparse.ArgumentParser(prog=prog, **m)
        for decl in decls:
            self.AddParameter(*decl.args, **decl.kwargs)

    def AddSubparsers(self, *args):
        def GetParser(**kwargs):
            return kwargs['parser']

        sp = self.p.add_subparsers(parser_class=GetParser, dest='command')
        for parser in args:
            sp.add_parser(parser.p.prog, parser=parser.p)
        return self

    def AddParameter(self, *args, **kwargs):
        """Adds a parameter and returns self."""
        m = kwargs
        if 'default' not in m:
            m['default'] = argparse.SUPPRESS
        if 'dest' in m:
            self.p.add_argument(*args, **m)
        else:
            for arg in args:
                if 'dest' in m:
                    del m['dest']
                if arg[0] == '-':
                    # Rename -l/--list to _l/__list, to preserve the '-/--' prefix
                    m['dest'] = '_%s%s' % ('_' if arg[1] == '-' else arg[1], arg[2:])
                self.p.add_argument(arg, **m)
        return self

    def parse_args(self, args, namespace=None):  # pylint: disable=g-bad-name
        ret = []
        if namespace is None:
            namespace = ParameterNamespace(ret)
        try:
            self.p.parse_args(args, namespace)
        except:
            raise ValueError
        return ret


class DAction(argparse.Action):
    """An argparse action that concatenates "-D" "x=y" to "-Dx=y"."""

    def __call__(self, parser, namespace, value, name):
        setattr(namespace, self.dest + value[0], True)


def _CreateParser():
    """Creates our parameter parser, which accepts a restricted set of commands.

    Returns:
       A new ParameterParser.
    """

    idevice_app_runner = ParameterParser(
        'idevice-app-runner',
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter),
        ParameterDecl('-D', type=str, nargs='*', action=DAction),
        ParameterDecl('-s', '--start', type=str),
        ParameterDecl('--args', type=str, nargs=argparse.REMAINDER))

    idevice_id = ParameterParser(
        'idevice_id',
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-l', '--list', action='store_true'))

    idevice_date = ParameterParser(
        'idevicedate',
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter))

    idevice_diagnostics = ParameterParser(
        'idevicediagnostics',
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter),
        ParameterDecl('command', type=str, choices=['diagnostics']),
        ParameterDecl('option', type=str, choices=['All', 'WiFi']))

    idevice_image_mounter = ParameterParser(
        'ideviceimagemounter',
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-l', '--list', action='store_true'),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter),
        ParameterDecl('image', type=InputFileParameter),
        ParameterDecl('signature', type=InputFileParameter))

    idevice_info = ParameterParser(
        'ideviceinfo',
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-k', '--key', type=str),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter),
        ParameterDecl('-q', '--domain', type=str),
        ParameterDecl('-s', '--simple', action='store_true'),
        ParameterDecl('-x', '--xml', action='store_true'))

    idevice_installer = ParameterParser(
        'ideviceinstaller',
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter),
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-i', '--install', type=InputFileParameter),
        ParameterDecl('-l', '--list', '--list-apps', action='store_true'),
        ParameterDecl('-o', '--options', type=str),
        ParameterDecl('-U', '--uninstall', type=str))

    idevicefs_ls = ParameterParser(
        'ls',
        ParameterDecl('-F', action='store_true'),
        ParameterDecl('-R', action='store_true'),
        ParameterDecl('-l', action='store_true'),
        ParameterDecl('remote', type=str, nargs=argparse.OPTIONAL))

    idevicefs_pull = ParameterParser(
        'pull',
        ParameterDecl('remote', type=str),
        ParameterDecl('local', type=OutputFileParameter))

    idevicefs_push = ParameterParser(
        'push',
        ParameterDecl('local', type=InputFileParameter),
        ParameterDecl('remote', type=str, nargs=argparse.OPTIONAL))

    idevicefs_rm = ParameterParser(
        'rm',
        ParameterDecl('-d', action='store_true'),
        ParameterDecl('-f', action='store_true'),
        ParameterDecl('-R', action='store_true'),
        ParameterDecl('remote', type=str))

    idevicefs_parsers = [
        ParameterParser('help'),
        idevicefs_ls,
        idevicefs_pull, idevicefs_push, idevicefs_rm]

    idevice_fs = ParameterParser(
        'idevicefs',
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter))
    idevice_fs.AddSubparsers(*idevicefs_parsers)

    idevice_screenshot = ParameterParser(
        'idevicescreenshot',
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter),
        ParameterDecl('local', type=OutputFileParameter))

    idevice_syslog = ParameterParser(
        'idevicesyslog',
        ParameterDecl('-d', '--debug', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-u', '--uuid', type=IOSDeviceIdParameter))

    idevice_parser = [
        idevice_app_runner, idevice_date, idevice_diagnostics, idevice_fs,
        idevice_id, idevice_image_mounter, idevice_info, idevice_installer,
        idevice_screenshot, idevice_syslog]

    adb_connect = ParameterParser(
        'connect',
        ParameterDecl('host', type=str))

    adb_devices = ParameterParser(
        'devices',
        ParameterDecl('-l', action='store_true'))

    adb_install = ParameterParser(
        'install',
        ParameterDecl('-r', action='store_true'),
        ParameterDecl('-s', action='store_true'),
        ParameterDecl('file', type=InputFileParameter))

    adb_logcat = ParameterParser(
        'logcat',
        ParameterDecl('-B', action='store_true'),
        ParameterDecl('-b', type=str),
        ParameterDecl('-c', action='store_true'),
        ParameterDecl('-d', action='store_true'),
        ParameterDecl('-f', type=str),
        ParameterDecl('-g', action='store_true'),
        ParameterDecl('-h', '--help', action='store_true'),
        ParameterDecl('-n', type=int),
        ParameterDecl('-r', type=int),
        ParameterDecl('-s', action='store_true'),
        ParameterDecl('-t', type=int),
        ParameterDecl('-v', type=str),
        ParameterDecl('filterspecs', nargs=argparse.REMAINDER))

    adb_pull = ParameterParser(
        'pull',
        ParameterDecl('remote', type=str),
        ParameterDecl('local', type=OutputFileParameter))

    adb_push = ParameterParser(
        'push',
        ParameterDecl('local', type=InputFileParameter),
        ParameterDecl('remote', type=str))

    adb_root = ParameterParser(
        'root')

    adb_shell = ParameterParser(
        'shell',
        ParameterDecl('arg0', type=str),  # Must have at least one arg
        ParameterDecl('args', nargs=argparse.REMAINDER))

    adb_uninstall = ParameterParser(
        'uninstall',
        ParameterDecl('-k', action='store_true'),
        ParameterDecl('package', type=str))

    adb_waitfordevices = ParameterParser(
        'wait-for-device')

    adb_parsers = [
        ParameterParser('help'),
        adb_connect, adb_devices, adb_install, adb_logcat, adb_pull,
        adb_push, adb_root, adb_shell, adb_uninstall, adb_waitfordevices]

    adb_parser = ParameterParser(
        'adb',
        ParameterDecl('-s', type=AndroidSerialParameter))
    adb_parser.AddSubparsers(*adb_parsers)

    parser = ParameterParser(None)
    parser.AddSubparsers(adb_parser, *idevice_parser)

    return parser


# Must be defined after _CreateParser().
#
# We could define this at the top of our file, but only if we wrap it to defer
# the eval to first use, e.g.:
#   PARSER = LazyProxy(lambda: _CreateParser())  # intercept __getattribute__
# but that's more confusing than it's worth.


if __name__ == '__main__':
    main(sys.argv)
