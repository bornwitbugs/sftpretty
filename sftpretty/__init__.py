from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from functools import partial
from logging import basicConfig, getLogger, DEBUG, debug, ERROR, error, INFO, info
from os import environ, utime
from paramiko import hostkeys, SFTPClient, Transport, util
from paramiko import SSHException, AuthenticationException
from paramiko import AgentKey, DSSKey, ECDSAKey, Ed25519Key, RSAKey
from pathlib import Path
from sftpretty.exceptions import CredentialException, ConnectionException, HostKeysException
from sftpretty.helpers import _callback, hash, retry, st_mode_to_int
from socket import gaierror
from stat import S_ISDIR, S_ISREG
from uuid import uuid4

__version__ = '0.0.1'
# pylint: disable = R0913,C0302

basicConfig(level=INFO)
log = getLogger(__name__)

class CnOpts(object):
    '''additional connection options beyond authentication

    :ivar bool|str log: initial value: False -
        log connection/handshake details? If set to True,
        sftpretty creates a temporary file and logs to that.  If set to a valid
        path and filename, sftpretty logs to that.  The name of the logfile can
        be found at  ``.logfile``
    :ivar bool compression: initial value: False - Enables compression on the
        transport, if set to True.
    :ivar list|None ciphers: initial value: None -
        List of ciphers to use in order.
    :ivar paramiko.hostkeys.HostKeys|None hostkeys: HostKeys object to use for
        host key checking.
    :param filepath|None knownhosts: initial value: None - file to load
        hostkeys. If not specified, uses ~/.ssh/known_hosts
    :returns: (obj) CnOpts - A connection options object, used for passing
        extended options to the Connection
    :raises HostKeysException:
    '''
    def __init__(self, knownhosts=None):
        self.log = False
        self.compression = False
        self.ciphers = None
        self.digests = None
        self.kex = None
        if knownhosts is None:
            knownhosts = Path('~/.ssh/known_hosts').expanduser().as_posix()
        self.hostkeys = hostkeys.HostKeys()
        try:
            self.hostkeys.load(knownhosts)
        except IOError:
            # Can't find known_hosts in the standard place
            raise HostKeysException('Failed to load HostKeys from [{0}]. You \
                                    will need to explicitly load HostKeys \
                                    (cnopts.hostkeys.load(filename)) or disable \
                                    HostKey checking (cnopts.hostkeys = None).'
                                    .format(knownhosts))
        else:
            if len(self.hostkeys.items()) == 0:
                raise HostKeysException('No host keys found!')

    def get_hostkey(self, host):
        '''return the matching hostkey to use for verification for the host
        indicated or raise an SSHException'''
        kval = self.hostkeys.lookup(host)
        # None | {key_type: private_key}
        if kval is None:
            raise SSHException('No hostkey for host [{0}] found.'
                               .format(str(host)))

        # Return the private key from the dictionary
        return list(kval.values())[0]


class Connection(object):
    '''Connects and logs into the specified hostname.
    Arguments that are not given are guessed from the environment.

    :param str host:
        The Hostname or IP of the remote machine.
    :param str|None username: *Default: None* -
        Your username at the remote machine.
    :param str|obj|None private_key: *Default: None* -
        path to private key file(str) or paramiko.AgentKey
    :param str|None password: *Default: None* -
        Your password at the remote machine.
    :param int port: *Default: 22* -
        The SSH port of the remote machine.
    :param str|None private_key_pass: *Default: None* -
        password to use, if private_key is encrypted.
    :param list|None ciphers: *Deprecated* -
        see ``sftpretty.CnOpts`` and ``cnopts`` parameter
    :param bool|str log: *Deprecated* -
        see ``sftpretty.CnOpts`` and ``cnopts`` parameter
    :param None|CnOpts cnopts: *Default: None* - extra connection options
        set in a CnOpts object.
    :param str|None default_path: *Default: None* -
        set a default path upon connection.
    :returns: (obj) connection to the requested host
    :raises ConnectionException:
    :raises CredentialException:
    :raises SSHException:
    :raises AuthenticationException:
    :raises PasswordRequiredException:
    :raises HostKeysException:

    '''
    def __init__(self, host, username=None, private_key=None, password=None,
                 port=22, private_key_pass=None, cnopts=None,
                 default_path=None):
        # Starting point for transport.connect options
        self._tconnect = {
                          'username': username, 'password': password,
                          'hostkey': None, 'pkey': None
                         }
        self._cnopts = cnopts or CnOpts()
        self._default_path = default_path
        # Check that we have a hostkey to verify
        if self._cnopts.hostkeys is not None:
            self._tconnect['hostkey'] = self._cnopts.get_hostkey(host)

        self._sftp_live = False
        self._sftp = None
        self._set_logging()
        self._set_username()
        # Begin the SSH transport.
        self._transport = None
        self._start_transport(host, port)
        self._set_authentication(password, private_key, private_key_pass)
        self._transport.connect(**self._tconnect)

    def _set_authentication(self, password, private_key, private_key_pass):
        '''Authenticate the transport. prefer password if given'''
        if password is None:
            # Use private key.
            if not private_key:
                raise CredentialException('No password or key specified.')
            # Use the paramiko agent or provided key object
            elif isinstance(private_key,
                            (AgentKey, DSSKey, ECDSAKey, Ed25519Key, RSAKey)):
                self._tconnect['pkey'] = private_key
            # Use path provided
            elif isinstance(private_key, str):
                private_key_file = Path(private_key).expanduser().as_posix()
                if Path(private_key_file).is_file():
                    try:
                        with open(private_key_file, 'rb') as key:
                            key_head = key.readline().decode('utf8')
                        if 'DSA' in key_head:
                            key_type = DSSKey
                        elif 'EC' in key_head:
                            key_type = ECDSAKey
                        elif 'OPENSSH' in key_head:
                            key_type = Ed25519Key
                        elif 'RSA' in key_head:
                            key_type = RSAKey
                        else:
                            raise CredentialException('Unable to identify key \
                                                      type from file provided, \
                                                      [{0}]!'
                                                      .format(private_key_file))
                    except PermissionError as err:
                        raise err
                    finally:
                        try:
                            if not private_key_pass:
                                self._tconnect['pkey'] = key_type.from_private_key_file(private_key_file)
                            else:
                                self._tconnect['pkey'] = key_type.from_private_key_file(private_key_file, private_key_pass)
                        except SSHException as err:
                            raise err
                else:
                    raise CredentialException('Path provided is not a file or \
                                               does not exist, please revise \
                                               and provide a path to a valid \
                                               private key')

    def _set_logging(self):
        '''Set logging for connection'''
        if self._cnopts.log:
            if isinstance(self._cnopts.log, bool):
                # Log to a temporary file.
                self._cnopts.log = Path('/tmp/sftpretty-{0}.txt'
                                        .format(uuid4())).touch()
            elif isinstance(self._cnopts.log, str):
                self._cnopts.log = Path(self._cnopts.log).touch()
            util.log_to_file(self._cnopts.log)

    def _set_username(self):
        '''Set the username for the connection. If not passed, then look to
        the environment. Still nothing? Throw exception.'''
        if self._tconnect['username'] is None:
            self._tconnect['username'] = environ.get('LOGNAME', None)
            if self._tconnect['username'] is None:
                raise CredentialException('No username specified.')

    def _sftp_channel(self):
        '''Establish new SFTP channel.'''
        self._sftp = SFTPClient.from_transport(self._transport)
        if self._default_path is not None:
            log.info('Default Path: [{0}]'.format(self._default_path))
            self._sftp.chdir(self._default_path)
        self._sftp_live = True

    def _sftp_connect(self):
        '''Establish the SFTP connection.'''
        if not self._sftp_live:
            self._sftp = SFTPClient.from_transport(self._transport)
            if self._default_path is not None:
                log.info('Default Path: [{0}]'.format(self._default_path))
                self._sftp.chdir(self._default_path)
            self._sftp_live = True

    def _start_transport(self, host, port):
        '''Start the transport and set the ciphers if specified.'''
        try:
            self._transport = Transport((host, port))
            self._transport.set_log_channel(host)
            self._transport.use_compression(self._cnopts.compression)
            # Set security ciphers if set
            if self._cnopts.ciphers is not None:
                ciphers = self._cnopts.ciphers
                self._transport.get_security_options().ciphers = ciphers
            # Set security digests if set
            if self._cnopts.digests is not None:
                digests = self._cnopts.digests
                self._transport.get_security_options().digests = digests
            # Set security kex if set
            if self._cnopts.kex is not None:
                kex = self._cnopts.kex
                self._transport.get_security_options().kex = kex
        except (AttributeError, gaierror):
            # Couldn't connect
            raise ConnectionException(host, port)

    def get(self, remotepath, localpath=None, callback=None,
            preserve_mtime=False, exceptions=None, tries=None, backoff=2,
            delay=1, logger=log, silent=False):
        '''Copies a file between the remote host and the local host.

        :param str remotepath: the remote path and filename, source
        :param str localpath:
            the local path and filename to copy, destination. If not specified,
            file is copied to local current working directory
        :param callable callback:
            optional callback function (form: ``func(int, int)``) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool preserve_mtime: *Default: False*
            make the modification time(st_mtime) on the
            local file match the time on the remote. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: Default is 2. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: Default is 1. Initial delay between retries in
            seconds.
        :param logging.Logger logger: Defaults to built in logger object.
            Logger to use. If None, print.
        :param bool silent: Default is False. If set then no logging will
            be attempted.

        :returns: None

        :raises: IOError

        '''
        @retry(exceptions, tries=tries, backoff=backoff, delay=delay,
               logger=logger, silent=silent)
        def _get(self, remotepath, localpath=None, callback=None,
                 preserve_mtime=False):
            self._sftp_channel()

            channel = self._sftp.get_channel()
            channel.set_name(Path(remotepath).name)

            if not callback:
                callback = partial(_callback, remotepath, logger=logger)

            if not localpath:
                localpath = Path(remotepath).name

            self._sftp.get(remotepath, localpath=localpath, callback=callback)

            if preserve_mtime:
                remote_attributes = self._sftp.stat(remotepath)
                utime(localpath, (remote_attributes.st_atime,
                                  remote_attributes.st_mtime))

            channel.close()

        _get(self, remotepath, localpath=localpath, callback=callback,
             preserve_mtime=preserve_mtime)

    def get_d(self, remotedir, localdir, callback=None, pattern=None,
              preserve_mtime=False, exceptions=None, tries=None, backoff=2,
              delay=1, logger=log, silent=False):
        '''get the contents of remotedir and write to locadir. (non-recursive)

        :param str remotedir: the remote directory to copy from (source)
        :param str localdir: the local directory to copy to (target)
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param str pattern: filter applied to filenames to transfer only subset
            of files in a directory.
        :param bool preserve_mtime: *Default: False*
            preserve modification time on files
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns: None

        :raises: Any exception raised by operations will be passed through.
        '''
        self._sftp_channel()

        channel = self._sftp.get_channel()
        channel.set_name(Path(remotedir).stem)

        if not Path(localdir).is_dir():
            log.info('Creating Folder [{0}]'.format(localdir))
            Path(localdir).mkdir(parents=True)

        if not pattern:
            paths = [
                     (Path(remotedir).joinpath(attribute.filename).as_posix(),
                     Path(localdir).joinpath(attribute.filename).as_posix(),
                     callback, preserve_mtime, exceptions, tries, backoff, delay,
                     logger, silent)
                     for attribute in self._sftp.listdir_attr(remotedir)
                     if S_ISREG(attribute.st_mode)
                    ]
        else:
            paths = [
                     (Path(remotedir).joinpath(attribute.filename).as_posix(),
                     Path(localdir).joinpath(attribute.filename).as_posix(),
                     callback, preserve_mtime, exceptions, tries, backoff, delay,
                     logger, silent)
                     for attribute in self._sftp.listdir_attr(remotedir)
                     if S_ISREG(attribute.st_mode)
                     and '{0}'.format(pattern) in attribute.filename
                    ]

        if paths != []:
            with ThreadPoolExecutor(thread_name_prefix=hash(paths)) as executor:
                threads = {
                           executor.submit(self.get, remote, local,
                           callback=callback, preserve_mtime=preserve_mtime,
                           exceptions=exceptions, tries=tries, backoff=backoff,
                           delay=delay, logger=logger, silent=silent): remote
                           for remote, local, callback, preserve_mtime,
                           exceptions, tries, backoff, delay, logger, silent in
                           paths
                          }
                for future in as_completed(threads):
                    name = threads[future]
                    try:
                        future.result()
                    except Exception as err:
                        log.error('{0} Thread: [{1}] [FAILED]'
                                  .format(channel.get_name(), name))
                        channel.close()
                        raise err
                    else:
                        log.info('{0} Thread: [{1}] [COMPLETE]'
                                 .format(channel.get_name(), name))
                        channel.close()
        else:
            log.info('No files found in directory [{0}]'.format(remotedir))
            channel.close()

    def get_r(self, remotedir, localdir, callback=None, pattern=None,
              preserve_mtime=False, exceptions=None, tries=None, backoff=2,
              delay=1, logger=log, silent=False):
        '''recursively copy remotedir structure to localdir

        :param str remotedir: the remote directory to recursively copy from
        :param str localdir: the local directory to recursively copy to
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param str pattern: filter applied to filenames to transfer only subset
            of files in a directory.
        :param bool preserve_mtime: *Default: False*
            preserve modification time on files
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns: None

        :raises: Any exception raised by operations will be passed through.

        '''
        directories = {}

        paths = self.remotetree(directories, remotedir, localdir, recurse=True)
        paths['root'] = [(remotedir, localdir)]

        for tld in paths.keys():
            for remote, local in paths[tld]:
                self.get_d(remote, local, callback=callback,
                           pattern=pattern, preserve_mtime=preserve_mtime,
                           exceptions=exceptions, tries=tries, backoff=backoff,
                           delay=delay, logger=logger, silent=silent)

    def getfo(self, remotepath, flo, callback=None, exceptions=None,
              tries=None, backoff=2, delay=1, logger=log, silent=False):
        '''Copy a remote file (remotepath) to a file-like object, flo.

        :param str remotepath: the remote path and filename, source
        :param flo: open file like object to write, destination.
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns: (int) the number of bytes written to the opened file object

        :raises: Any exception raised by operations will be passed through.

        '''
        @retry(exceptions, tries=tries, backoff=backoff, delay=delay,
               logger=logger, silent=silent)
        def _getfo(self, remotepath, flo, callback=None):
            self._sftp_channel()

            channel = self._sftp.get_channel()
            channel.set_name(Path(remotepath).name)

            if not callback:
                callback = partial(_callback, remotepath, logger=logger)

            return self._sftp.getfo(remotepath, flo, callback=callback)

            channel.close()

        return _getfo(self, remotepath, flo, callback=callback)

    def put(self, localpath, remotepath=None, callback=None, confirm=True,
            preserve_mtime=False, exceptions=None, tries=None, backoff=2,
            delay=1, logger=log, silent=False):
        '''Copies a file between the local host and the remote host.

        :param str localpath: the local path and filename
        :param str remotepath:
            the remote path, else the remote :attr:`.pwd` and filename is used.
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size
        :param bool preserve_mtime: *Default: False*
            make the modification time(st_mtime) on the
            remote file match the time on the local. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns:
            (obj) SFTPAttributes containing attributes about the given file

        :raises IOError: if remotepath doesn't exist
        :raises OSError: if localpath doesn't exist

        '''
        @retry(exceptions, tries=tries, backoff=backoff, delay=delay,
               logger=logger, silent=silent)
        def _put(self, localpath, remotepath=None, callback=None,
                 confirm=True, preserve_mtime=False):
            self._sftp_channel()

            channel = self._sftp.get_channel()
            channel.set_name(Path(localpath).name)

            if not callback:
                callback = partial(_callback, localpath, logger=logger)

            if not remotepath:
                remotepath = Path(localpath).name

            remote_attributes = self._sftp.put(localpath,
                                               remotepath=remotepath,
                                               callback=callback,
                                               confirm=confirm)

            if preserve_mtime:
                local_attributes = Path(localpath).stat()
                local_times = (local_attributes.st_atime,
                               local_attributes.st_mtime)
                self._sftp.utime(remotepath, local_times)
                remote_attributes = self._sftp.stat(remotepath)

            channel.close()

            return remote_attributes

        return _put(self, localpath, remotepath=remotepath, callback=callback,
                    confirm=confirm, preserve_mtime=preserve_mtime)

    def put_d(self, localdir, remotedir, callback=None, confirm=True,
              preserve_mtime=False, exceptions=None, tries=None, backoff=2,
              delay=1, logger=log, silent=False):
        '''Copies a local directory's contents to a remotepath

        :param str localdir: the local path to copy (source)
        :param str remotedir:
            the remote path to copy to (target)
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size
        :param bool preserve_mtime: *Default: False*
            make the modification time(st_mtime) on the
            remote file match the time on the local. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns: None

        :raises IOError: if remotedir doesn't exist
        :raises OSError: if localdir doesn't exist
        '''
        self._sftp_channel()

        channel = self._sftp.get_channel()
        channel.set_name(Path(localdir).stem)

        self.mkdir_p(remotedir)

        paths = [
                 (localpath.as_posix(),
                 Path(remotedir).joinpath(localpath.relative_to('/').as_posix()).as_posix(),
                 callback, confirm, preserve_mtime, exceptions, tries, backoff,
                 delay, logger, silent)
                 for localpath in Path(localdir).iterdir() if localpath.is_file()
                ]

        if paths != []:
            with ThreadPoolExecutor(thread_name_prefix=hash(paths)) as executor:
                threads = {
                           executor.submit(self.put, local, remote,
                           callback=callback, confirm=confirm,
                           preserve_mtime=preserve_mtime, exceptions=exceptions,
                           tries=tries, backoff=backoff, delay=delay,
                           logger=logger, silent=silent): local
                           for local, remote, callback, confirm, preserve_mtime,
                           exceptions, tries, backoff, delay, logger, silent
                           in paths
                          }
                for future in as_completed(threads):
                    name = threads[future]
                    try:
                        future.result()
                    except Exception as err:
                        log.error('{0} Thread: [{1}] [FAILED]'
                                  .format(channel.get_name(), name))
                        channel.close()
                        raise err
                    else:
                        log.info('{0} Thread: [{1}] [COMPLETE]'
                                 .format(channel.get_name(), name))
                        channel.close()
        else:
            log.info('No files found in directory [{0}]'.format(localdir))
            channel.close()

    def put_r(self, localdir, remotedir, callback=None, confirm=True,
              preserve_mtime=False, exceptions=None, tries=None, backoff=2,
              delay=1, logger=log, silent=False):
        '''Recursively copies a local directory's contents to a remotepath

        :param str localdir: the local path to copy (source)
        :param str remotedir:
            the remote path to copy to (target)
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size
        :param bool preserve_mtime: *Default: False*
            make the modification time(st_mtime) on the
            remote file match the time on the local. (st_atime can differ
            because stat'ing the localfile can/does update it's st_atime)
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns: None

        :raises IOError: if remotedir doesn't exist
        :raises OSError: if localdir doesn't exist
        '''
        directories = {}

        paths = self.localtree(directories, localdir, remotedir, recurse=True)
        paths['root'] = [(localdir, remotedir)]

        for tld in paths.keys():
            for local, remote in paths[tld]:
                self.put_d(local, remote, callback=callback, confirm=confirm,
                           preserve_mtime=preserve_mtime, exceptions=exceptions,
                           tries=tries, backoff=backoff, delay=delay,
                           logger=logger, silent=silent)

    def putfo(self, flo, remotepath=None, file_size=0, callback=None,
              confirm=True, exceptions=None, tries=None, backoff=2,
              delay=1, logger=log, silent=False):
        '''Copies the contents of a file like object to remotepath.

        :param flo: a file-like object that supports .read()
        :param str remotepath: the remote path.
        :param int file_size:
            the size of flo, if not given the second param passed to the
            callback function will always be 0.
        :param callable callback:
            optional callback function (form: ``func(int, int``)) that accepts
            the bytes transferred so far and the total bytes to be transferred.
        :param bool confirm:
            whether to do a stat() on the file afterwards to confirm the file
            size
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns:
            (obj) SFTPAttributes containing attributes about the given file

        :raises: TypeError, if remotepath not specified, any underlying error

        '''
        @retry(exceptions, tires=tries, backoff=backoff, delay=delay,
               logger=logger, silent=silent)
        def _putfo(self, flo, remotepath=None, file_size=0, callback=None,
                   confirm=True):
            self._sftp_channel()

            channel = self._sftp.get_channel()
            channel.set_name(Path(localpath).name)

            if not callback:
                callback = partial(_callback, flo, logger=logger)

            return self._sftp.putfo(flo, remotepath=remotepath,
                                    file_size=file_size,
                                    callback=callback, confirm=confirm)

            channel.close()

        return _putfo(self, flo, remotepath=remotepath, file_size=file_size,
                      callback=callback, confirm=confirm)

    def execute(self, command,
                exceptions=None, tries=None, backoff=2, delay=1, logger=log,
                silent=False):
        '''Execute the given commands on a remote machine.  The command is
        executed without regard to the remote :attr:`.pwd`.

        :param str command: the command to execute.
        :param Exception execeptions: Exception(s) to check. May be a tuple of
            exceptions to check. IOError or IOError(errno.ECOMM) or (IOError,)
            or (ValueError, IOError(errno.ECOMM))
        :param int tries: Times to try (not retry) before giving up.
        :param int backoff: *Default is 2*. Backoff multiplier. Default will
            double the delay each retry.
        :param int delay: *Default is 1*. Initial delay between retries in
            seconds.
        :param logging.Logger logger: *Defaults to built in logger object*.
            Logger to use. If None, print.
        :param bool silent: *Default is False*. If set then no logging will
            be attempted.

        :returns: (list of str) representing the results of the command

        :raises: Any exception raised by command will be passed through.

        '''
        @retry(exceptions, backoff=backoff, delay=delay, logger=logger,
               silent=silent, tries=tries)
        def _execute(self, command):
            channel = self._transport.open_session()
            channel.exec_command(command)
            output = channel.makefile('rb', -1).readlines()

            if output:
                return output
            else:
                return channel.makefile_stderr('rb', -1).readlines()

        _execute(self, command)

    @contextmanager
    def cd(self, remotepath=None):
        '''Context manager that can change to a optionally specified remote
        directory and restores the old pwd on exit.

        :param str|None remotepath: *Default: None* -
            remotepath to temporarily make the current directory

        :returns: None

        :raises: IOError, if remote path doesn't exist
        '''
        original_path = self.pwd
        try:
            if remotepath is not None:
                self.chdir(remotepath)
            yield
        except IOError as err:
            self.mkdir_p(remotepath)
            self.cd(remotepath)
        finally:
            self.chdir(original_path)

    def chdir(self, remotepath):
        '''Change the current working directory on the remote

        :param str remotepath: the remote path to change to

        :returns: None

        :raises: IOError, if path does not exist

        '''
        self._sftp_connect()

        self._sftp.chdir(remotepath)

    def chmod(self, remotepath, mode=777):
        '''Set the mode of a remotepath to mode, where mode is an integer
        representation of the octal mode to use.

        :param str remotepath: the remote path/file to modify
        :param int mode: *Default: 777* -
            int representation of octal mode for directory

        :returns: None

        :raises: IOError, if the file doesn't exist

        '''
        self._sftp_connect()

        self._sftp.chmod(remotepath, mode=int(str(mode), 8))

    def chown(self, remotepath, uid=None, gid=None):
        '''Set uid and/or gid on a remotepath, you may specify either or both.
        Unless you have **permission** to do this on the remote server, you
        will raise an IOError: 13 - permission denied

        :param str remotepath: the remote path/file to modify
        :param int uid: the user id to set on the remotepath
        :param int gid: the group id to set on the remotepath

        :returns: None

        :raises:
            IOError, if you don't have permission or the file doesn't exist

        '''
        self._sftp_connect()

        if uid is None or gid is None:
            if uid is None and gid is None:
                return
            remote_attributes = self._sftp.stat(remotepath)
            if uid is None:
                uid = remote_attributes.st_uid
            if gid is None:
                gid = remote_attributes.st_gid

        self._sftp.chown(remotepath, uid=uid, gid=gid)

    def close(self):
        '''Closes the connection and cleans up.'''
        # Close SFTP Connection.
        if self._sftp_live:
            self._sftp.close()
            self._sftp_live = False
        # Close the SSH Transport.
        if self._transport:
            self._transport.close()
            self._transport = None
        # Clean up any loggers
        if self._cnopts.log:
            # if handlers are active they hang around until the app Exits
            # this closes and removes the handlers if in use at close
            lgr = getLogger(__name__)
            if lgr:
                lgr.handlers = []

    def exists(self, remotepath):
        '''Test whether a remotepath exists.

        :param str remotepath: the remote path to verify

        :returns: (bool) True, if remotepath exists, else False

        '''
        self._sftp_connect()

        try:
            self._sftp.stat(remotepath)
        except IOError:
            return False   

        return True

    def getcwd(self):
        '''Return the current working directory on the remote. This is a wrapper
        for paramiko's method and not to be confused with the SFTP command,
        cwd.

        :returns: (str) the current remote path. None, if not set.

        '''
        self._sftp_connect()

        return self._sftp.getcwd()

    def isdir(self, remotepath):
        '''Return true, if remotepath is a directory

        :param str remotepath: the path to test

        :returns: (bool)

        '''
        self._sftp_connect()

        try:
            result = S_ISDIR(self._sftp.stat(remotepath).st_mode)
        except IOError:
            # No such directory
            result = False

        return result

    def isfile(self, remotepath):
        '''Return true if remotepath is a file

        :param str remotepath: the path to test

        :returns: (bool)

        '''
        self._sftp_connect()

        try:
            result = S_ISREG(self._sftp.stat(remotepath).st_mode)
        except IOError:
            # No such file
            result = False

        return result

    def lexists(self, remotepath):
        '''Test whether a remotepath exists.  Returns True for broken symbolic
        links

        :param str remotepath: the remote path to verify

        :returns: (bool), True, if lexists, else False

        '''
        self._sftp_connect()

        try:
            self._sftp.lstat(remotepath)
        except IOError:
            return False

        return True

    def listdir(self, remotepath='.'):
        '''Return a list of files/directories for the given remote path.
        Unlike, paramiko, the directory listing is sorted.

        :param str remotepath: path to list on the server

        :returns: (list of str) directory entries, sorted

        '''
        self._sftp_connect()

        return sorted(self._sftp.listdir(remotepath))

    def listdir_attr(self, remotepath='.'):
        '''return a list of SFTPAttribute objects of the files/directories for
        the given remote path. The list is in arbitrary order. It does not
        include the special entries '.' and '..'.

        The returned SFTPAttributes objects will each have an additional field:
        longname, which may contain a formatted string of the file's
        attributes, in unix format. The content of this string will depend on
        the SFTP server.

        :param str remotepath: path to list on the server

        :returns: (list of SFTPAttributes), sorted

        '''
        self._sftp_connect()

        return sorted(self._sftp.listdir_attr(remotepath),
                      key=lambda attribute: attribute.filename)

    def localtree(self, container, localdir, remotedir, recurse=True):
        '''recursively descend, depth first, the directory tree rooted at
        local directory.

        :param dict container: dictionary object to save directory tree
        :param str localdir:
            root of local directory to descend, use '.' to start at
            :attr:`.pwd`
        :param str remotedir:
            root of remote directory to append localdir to create new 
            path
        :param bool recurse: *Default: True* - should it recurse

        :returns: (dict) local directory tree

        :raises: Exception

        '''
        try:
            for localpath in Path(localdir).iterdir():
                if localpath.is_dir():
                    local = localpath.as_posix()
                    remote = Path(remotedir).joinpath(localpath.relative_to('/').as_posix()).as_posix()
                    if localdir in container.keys():
                        container[localdir].append((local, remote))
                    else:
                        container[localdir] = [(local, remote)]
                    if recurse:
                        self.localtree(container, local, remotedir,
                                       recurse=recurse)
        except Exception as err:
            raise err

        return(container)

    def lstat(self, remotepath):
        '''return information about file/directory for the given remote path,
        without following symbolic links. Otherwise, the same as .stat()

        :param str remotepath: path to stat

        :returns: (obj) SFTPAttributes object

        '''
        self._sftp_connect()

        return self._sftp.lstat(remotepath)

    def mkdir(self, remotepath, mode=777):
        '''Create a directory named remotepath with mode. On some systems,
        mode is ignored. Where it is used, the current umask value is first
        masked out.

        :param str remotepath: directory to create`
        :param int mode: *Default: 777* -
            int representation of octal mode for directory

        :returns: None

        '''
        self._sftp_connect()

        self._sftp.mkdir(remotepath, mode=int(str(mode), 8))

    def mkdir_p(self, remotedir, mode=777):
        '''Create all directories in remotedir path as needed, setting their
        mode to mode, if created.

        If remotedir already exists, silently complete. If a regular file is
        in the way, raise an exception.

        :param str remotedir: the directory structure to create
        :param int mode: *Default: 777* -
            int representation of octal mode for directory

        :returns: None

        :raises: OSError

        '''
        self._sftp_connect()

        try:
            if self.isdir(remotedir):
                pass
            elif self.isfile(remotedir):
                raise OSError('A file with the same name as the remotedir, \
                               [{0}], already exists.'.format(remotedir))
            else:
                parent = Path(remotedir).parent.as_posix()
                stem = Path(remotedir).stem
                if parent and not self.isdir(parent):
                    self.mkdir_p(parent, mode=mode)
                if stem:
                    self.mkdir(remotedir, mode=mode)
        except Exception as err:
            raise err

    def normalize(self, remotepath):
        '''Return the expanded path, w.r.t the server, of a given path.  This
        can be used to resolve symlinks or determine what the server believes
        to be the :attr:`.pwd`, by passing '.' as remotepath.

        :param str remotepath: path to be normalized

        :return: (str) normalized form of the given path

        :raises: IOError, if remotepath can't be resolved
        '''
        self._sftp_connect()

        return self._sftp.normalize(remotepath)

    def open(self, remote_file, mode='r', bufsize=-1):
        '''Open a file on the remote server.

        See http://paramiko-docs.readthedocs.org/en/latest/api/sftp.html for
        details.

        :param str remote_file: name of the file to open.
        :param str mode:
            mode (Python-style) to open file (always assumed binary)
        :param int bufsize: *Default: -1* - desired buffering

        :returns: (obj) SFTPFile, a handle the remote open file

        :raises: IOError, if the file could not be opened.

        '''
        self._sftp_connect()

        return self._sftp.open(remote_file, mode=mode, bufsize=bufsize)

    def readlink(self, remotelink):
        '''Return the target of a symlink (shortcut).  The result will be
        an absolute pathname.

        :param str remotelink: remote path of the symlink

        :return: (str) absolute path to target

        '''
        self._sftp_connect()

        return self._sftp.normalize(self._sftp.readlink(remotelink))

    def remotetree(self, container, remotedir, localdir, recurse=True):
        '''recursively descend, depth first, the directory tree rooted at
        remote directory.

        :param dict container: dictionary object to save directory tree
        :param str remotedir:
            root of remote directory to descend, use '.' to start at
            :attr:`.pwd`
        :param str localdir:
            root of local directory to append remotedir to create new path
        :param bool recurse: *Default: True*. should it recurse

        :returns: (dict) remote directory tree

        :raises: Exception

        '''
        self._sftp_channel()

        channel = self._sftp.get_channel()
        channel.set_name(Path(localdir).joinpath(remotedir).as_posix())

        try:
            for attribute in self.listdir_attr(remotedir):
                if S_ISDIR(attribute.st_mode):
                    remote = Path(remotedir).joinpath(attribute.filename).as_posix()
                    local = Path(localdir).joinpath(Path(remote).relative_to('/').as_posix()).as_posix()
                    if remotedir in container.keys():
                        container[remotedir].append((remote, local))
                    else:
                        container[remotedir] = [(remote, local)]
                    if recurse:
                        channel.close()
                        self.remotetree(container, remote, localdir,
                                        recurse=recurse)
        except Exception as err:
            channel.close()
            raise err

        return(container)

    def remove(self, remotefile):
        '''Remove the file @ remotefile, remotefile may include a path, if no
        path, then :attr:`.pwd` is used.  This method only works on files

        :param str remotefile: the remote file to delete

        :returns: None

        :raises: IOError
        '''
        self._sftp_connect()

        self._sftp.remove(remotefile)

    def rename(self, remote_src, remote_dest):
        '''Rename a file or directory on the remote host.

        :param str remote_src: the remote file/directory to rename

        :param str remote_dest: the remote file/directory to put it

        :returns: None

        :raises: IOError

        '''
        self._sftp_connect()

        self._sftp.rename(remote_src, remote_dest)

    def rmdir(self, remotepath):
        '''remove remote directory

        :param str remotepath: the remote directory to remove

        :returns: None

        '''
        self._sftp_connect()

        self._sftp.rmdir(remotepath)

    def stat(self, remotepath):
        '''Return information about file/directory for the given remote path

        :param str remotepath: path to stat

        :returns: (obj) SFTPAttributes

        '''
        self._sftp_connect()

        return self._sftp.stat(remotepath)

    def symlink(self, remote_src, remote_dest):
        '''create a symlink for a remote file on the server

        :param str remote_src: path of original file
        :param str remote_dest: path of the created symlink

        :returns: None

        :raises:
            any underlying error, IOError if something already exists at
            remote_dest

        '''
        self._sftp_connect()

        self._sftp.symlink(remote_src, remote_dest)

    def truncate(self, remotepath, size):
        '''Change the size of the file specified by path. Used to modify the
        size of the file, just like the truncate method on Python file objects.
        The new file size is confirmed and returned.

        :param str remotepath: remote file path to modify
        :param int|long size: the new file size

        :returns: (int) new size of file

        :raises: IOError, if file does not exist

        '''
        self._sftp_connect()

        self._sftp.truncate(remotepath, size)

        return self._sftp.stat(remotepath).st_size

    @property
    def active_ciphers(self):
        '''Get tuple of currently used local and remote ciphers.

        :returns:
            (tuple of  str) currently used ciphers (local_cipher,
            remote_cipher)

        '''
        return self._transport.local_cipher, self._transport.remote_cipher

    @property
    def active_compression(self):
        '''Get tuple of currently used local and remote compression.

        :returns:
            (tuple of  str) currently used compression (local_compression,
            remote_compression)

        '''
        local_compression = self._transport.local_compression
        remote_compression = self._transport.remote_compression

        return local_compression, remote_compression

    @property
    def logfile(self):
        '''return the name of the file used for logging or False it not logging

        :returns: (str)logfile or (bool) False

        '''
        return self._cnopts.log

    @property
    def pwd(self):
        '''return the current working directory

        :returns: (str) current working directory

        '''
        self._sftp_connect()

        return self._sftp.normalize('.')

    @property
    def remote_server_key(self):
        '''return the remote server's key'''
        return self._transport.get_remote_server_key()

    @property
    def security_options(self):
        '''return the available security options recognized by paramiko.

        :returns:
            (obj) security preferences of the ssh transport. These are tuples
            of acceptable `.ciphers`, `.digests`, `.key_types`, and key
            exchange algorithms `.kex`, listed in order of preference.

        '''
        return self._transport.get_security_options()

    @property
    def sftp_client(self):
        '''Give access to the underlying, connected paramiko SFTPClient object

        see http://paramiko-docs.readthedocs.org/en/latest/api/sftp.html

        :params: None

        :returns: (obj) the active SFTPClient object

        '''
        self._sftp_connect()

        return self._sftp

    @property
    def timeout(self):
        ''' (float|None) *Default: None* -
            get or set the underlying socket timeout for pending read/write
            ops.

        :returns:
            (float|None) seconds to wait for a pending read/write operation
            before raising socket.timeout, or None for no timeout
        '''
        self._sftp_connect()

        channel = self._sftp.get_channel()

        return channel.gettimeout()

    @timeout.setter
    def timeout(self, val):
        '''setter for timeout'''
        self._sftp_connect()

        channel = self._sftp.get_channel()

        channel.settimeout(val)

    def __del__(self):
        '''Attempt to clean up if not explicitly closed.'''
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        self.close()
