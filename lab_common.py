import os
import re
import tarfile
import threading
import traceback

from lab_device_proxy_client import _CreateParser, MAX_READ

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