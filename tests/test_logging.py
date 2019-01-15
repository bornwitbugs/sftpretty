'''test CnOpts.log param and temporary log file creation'''

import pytest

from common import conn, VFS
from pathlib import Path
from sftpretyy import CnOpts, Connection


def test_log_cnopt_user_file(sftpserver):
    '''test .logfile returns temp filename when CnOpts.log is set to True'''
    copts = conn(sftpserver)
    cnopts = CnOpts()
    cnopts.log = Path('~/my-logfile1.txt').expanduser().as_posix()
    cnopts.hostkeys.load('sftpserver.pub')
    copts['cnopts'] = cnopts
    with sftpserver.serve_content(VFS):
        with Connection(**copts) as sftp:
            sftp.listdir()
            assert sftp.logfile == cnopts.log
            assert Path(sftp.logfile).exists()
            logfile = sftp.logfile
        # cleanup
        Path(logfile).unlink()


def test_log_param_user_file(sftpserver):
    '''test .logfile returns temp filename when log param is set to True'''
    copts = conn(sftpserver)
    copts['log'] = Path('~/my-logfile.txt').expanduser().as_posix()
    with sftpserver.serve_content(VFS):
        with Connection(**copts) as sftp:
            assert sftp.logfile == copts['log']
            assert Path(sftp.logfile).exists()
            logfile = sftp.logfile
        # cleanup
        Path(logfile).unlink()


def test_log_param_false(sftpserver):
    '''test .logfile returns false when logging is set to false'''
    with sftpserver.serve_content(VFS):
        with Connection(**conn(sftpserver)) as sftp:
            assert sftp.logfile is False


def test_log_cnopts_explicit_false(sftpserver):
    '''test .logfile returns false when CnOpts.log is set to false'''
    copts = conn(sftpserver)
    cnopts = CnOpts()
    cnopts.hostkeys.load('sftpserver.pub')
    copts['cnopts'] = cnopts
    with sftpserver.serve_content(VFS):
        with Connection(**copts) as sftp:
            assert sftp.logfile is False


def test_log_param_true(sftpserver):
    '''test .logfile returns temp filename when log param is set to True'''
    copts = conn(sftpserver)
    copts['log'] = True
    with sftpserver.serve_content(VFS):
        with Connection(**copts) as sftp:
            assert Path(sftp.logfile).exists()
            # and we are not writing to a file named 'True'
            assert sftp.logfile != copts['log']
            logfile = sftp.logfile
        # cleanup
        Path(logfile).unlink()


def test_log_cnopts_true(sftpserver):
    '''test .logfile returns temp filename when CnOpts.log is set to True'''
    copts = conn(sftpserver)
    cnopts = CnOpts()
    cnopts.log = True
    cnopts.hostkeys.load('sftpserver.pub')
    copts['cnopts'] = cnopts
    with sftpserver.serve_content(VFS):
        with Connection(**copts) as sftp:
            assert Path(sftp.logfile).exists()
            # and we are not writing to a file named 'True'
            assert sftp.logfile == cnopts.log
            logfile = sftp.logfile
        # cleanup
        Path(logfile).unlink()
