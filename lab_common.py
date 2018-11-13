import argparse
import os
import re
import tarfile
import threading
import traceback


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


PARSER = _CreateParser()


class ChunkHeader(object):
    """A parsed chunk header.

    We append "_" to all field names, which allows us to use reserved
    keywords, such as 'len' and 'id'.

    The choice of "_" as the suffix was arbitrary; it doesn't signify
    "private" access.
    """

    def __init__(self, id_=None):
        self.len_ = None
        self.id_ = id_
        self.in_ = None
        self.out_ = None
        self.is_absent_ = None
        self.is_empty_ = None
        self.is_tar_ = None

    def Parse(self, line):
        """Parses a formatted line.

        Args:
          line: a string, e.g. 'A;id=3,out=q\\r\\n'
        """
        try:
            if not line.endswith('\r\n'):
                raise ValueError('Missing "\\r\\n" suffix')
            len_and_csv = line[:-2].split(';', 1)
            if len(len_and_csv) > 1:
                for item in len_and_csv[1].split(','):
                    k, v = item.strip().split('=', 1)
                    self._Validate(k, v)
                    k += '_'  # Add our suffix
                    if not hasattr(self, k):
                        pass  # Ignore unknown keys
                    if k.startswith('is_'):
                        # Parse 'false' to False, not bool('false')
                        v = ('true' == v.lower())
                    setattr(self, k, v)
            self.len_ = max(0, int(len_and_csv[0].strip(), 16))
        except:
            raise ValueError('Invalid chunk header: %s', line)

    def Format(self):
        """Format the header into a Parse-able string.

        Returns:
          string, e.g. 'A;id=3,out=q\\r\\n'.
        """
        ret = ''
        for k, v in sorted(vars(self).iteritems()):
            if v is not None and k[-1] == '_' and k != 'len_':
                k = k[:-1]  # Remove our suffix
                v = str(v)
                self._Validate(k, v)
                ret += '%s%s=%s' % (',' if ret else '', k, v)
        ret = '%X;%s\r\n' % (self.len_, ret)
        return ret

    def _Validate(self, key, value):
        """Verifies that the given key=value pair is chunk-safe.

        Args:
          key: a string, e.g. "in".
          value: a string, e.g. "foo.xml".
        Raises:
          ValueError: if the key or value are invalid.
        """
        # Our fields are all simple lower-case names.
        if not re.match(r'[a-z][a-z_]*[a-z]$', key):
            raise ValueError('Illegal arg[%s] key: "%s"' % (self.id_, key))

        # This is very limit for now, but we could easily expand this to
        # allow other characters, e.g. whitespace.
        if not re.match(r'[-a-zA-Z0-9_\.]*$', value):
            raise ValueError('Unsupported arg[%s].%s character: "%s"' % (
                self.id_, key, value))

    def __eq__(self, other):
        return vars(self) == vars(other)

    def __ne__(self, other):
        return vars(self) != vars(other)

    def __repr__(self):
        return self.Format()[:-2]


def SendChunk(header, data, to_stream):
    """Sends a header and chunked data to the given stream.

    Args:
      header: A ChunkHeader, may be modified.
      data: Optional chunk content.
      to_stream: A socket.socket or a file object (e.g. StringIO buffer).
    """
    send = getattr(to_stream, 'send', None)
    if send is None:
        send = getattr(to_stream, 'write')

    if not data:
        # Send dummy data -- anything with length > 0
        header.is_empty_ = True
        data = '-'
    header.len_ = len(data)
    send(header.Format())
    send(data)
    send('\r\n')


def ReadExactly(from_stream, num_bytes):
    """Reads exactly num_bytes from a stream."""
    pieces = []
    bytes_read = 0
    while bytes_read < num_bytes:
        data = from_stream.read(min(MAX_READ, num_bytes - bytes_read))
        bytes_read += len(data)
        pieces.append(data)
    return ''.join(pieces)


def GetStack():
    # Get full_stack; see http://stackoverflow.com/questions/6086976
    trc = 'Traceback (most recent call last):\n'
    stackstr = (
        trc + ''.join(traceback.format_list(
            traceback.extract_stack()[:-2])) + '  ' +
        traceback.format_exc().lstrip(trc))
    return stackstr


class ChunkedOutputStream(object):
    """A chunked writer."""

    def __init__(self, header, to_stream):
        self._header = header
        self._to_stream = to_stream

    def write(self, buf):  # pylint: disable=g-bad-name
        if buf:
            SendChunk(self._header, buf, self._to_stream)

    def flush(self):  # pylint: disable=invalid-name
        self._to_stream.flush()

    def close(self):  # pylint: disable=invalid-name
        pass


def SendTar(from_fn, to_arcname, header, to_stream):
    """Sends a tar to an output stream.

    Args:
      from_fn: filename.
      to_arcname: archive name.
      header: chunk header line.
      to_stream: A socket.socket or a file object (e.g. StringIO buffer).
    """
    tar_stream = ChunkedOutputStream(header, to_stream)
    to_tar = tarfile.open(mode='w|gz', fileobj=tar_stream)
    # The from_fn has already been validated, so this is safe.
    to_tar.add(from_fn, arcname=to_arcname)
    to_tar.close()


class UntarPipe(object):
    """A pipe from the Response stream to the UntarThread reader."""

    def __init__(self):
        self.cv = threading.Condition()
        self.buf = []
        self.closed = False

    def write(self, data):  # pylint: disable=g-bad-name
        """Writes data, called by the Response stream."""
        with self.cv:
            if self.closed:
                raise RuntimeError('closed')
            self.buf.append(data)
            if len(self.buf) == 1:
                self.cv.notify()

    def read(self, max_bytes):  # pylint: disable=g-bad-name
        """Reads at most max_bytes, called by the UntarThread."""
        with self.cv:
            while not self.buf:
                if self.closed:
                    return ''
                self.cv.wait()
            if len(self.buf[0]) <= max_bytes:
                return self.buf.pop(0)
            ret = self.buf[0][:max_bytes]
            self.buf[0] = self.buf[0][max_bytes:]
            return ret

    def close(self):  # pylint: disable=g-bad-name
        with self.cv:
            if not self.closed:
                self.closed = True
                self.cv.notify()


class UntarThread(threading.Thread):
    """A thread that runs our UntarPipe."""

    def __init__(self, from_fp, to_fn):
        super(UntarThread, self).__init__()
        self._from_fp = from_fp
        to_fn = os.path.normpath(to_fn)
        to_dn = (to_fn if os.path.isdir(to_fn) else os.path.dirname(to_fn))
        to_dn = (to_dn if to_dn else '.')
        self._to_fn = to_fn
        self._to_dn = to_dn

    def run(self):
        # We used to set bufsize=512 here to prevent the tar buffer from reading
        # too many bytes (10k or EOF), which often ate into the next param's
        # chunks.  This is apparently no longer necessary, but I'm not sure
        # what changed, so let's keep this comment for now :/
        from_tar = tarfile.open(mode='r|*', fileobj=self._from_fp)
        while True:
            tar_entry = from_tar.next()
            if not tar_entry:
                break
            fn = os.path.normpath(os.path.join(self._to_dn, tar_entry.name))
            if (re.match(r'(\.\.|\/)', fn) if self._to_dn == '.' else
                not (fn == self._to_dn or fn.startswith(self._to_dn + '/'))):
                raise ValueError('Invalid tar entry path: %s' % tar_entry.name)
            from_tar.extract(tar_entry, self._to_dn)
        from_tar.close()


def Untar(to_fn):
    """Creates a threaded UntarPipe that accepts "write(data)" calls.

    Args:
      to_fn: Filename to untar into.
    Returns:
      An UntarPipe.
    """
    ret = UntarPipe()
    UntarThread(ret, to_fn).start()
    return ret


MAX_READ = 8192


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