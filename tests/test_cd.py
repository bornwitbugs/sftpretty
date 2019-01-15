'''test sftpretty.cd'''

import pytest

from common import conn, VFS
from sftpretty import cd, Connection


def test_cd_none(sftpserver):
    '''test sftpretty.cd with None'''
    with sftpserver.serve_content(VFS):
        with Connection(**conn(sftpserver)) as sftp:
            home = sftp.pwd
            with sftp.cd():
                sftp.chdir('pub')
                assert sftp.pwd == '/home/test/pub'
            assert home == sftp.pwd


def test_cd_path(sftpserver):
    '''test sftpretty.cd with a path'''
    with sftpserver.serve_content(VFS):
        with Connection(**conn(sftpserver)) as sftp:
            home = sftp.pwd
            with sftp.cd('pub'):
                assert sftp.pwd == '/home/test/pub'
            assert home == sftp.pwd


def test_cd_nested(sftpserver):
    '''test nested cd's'''
    with sftpserver.serve_content(VFS):
        with Connection(**conn(sftpserver)) as sftp:
            home = sftp.pwd
            with sftp.cd('pub'):
                assert sftp.pwd == '/home/test/pub'
                with sftp.cd('foo1'):
                    assert sftp.pwd == '/home/test/pub/foo1'
                assert sftp.pwd == '/home/test/pub'
            assert home == sftp.pwd


def test_cd_bad_path(sftpserver):
    '''test sftpretty.cd with a bad path'''
    with sftpserver.serve_content(VFS):
        with Connection(**conn(sftpserver)) as sftp:
            home = sftp.pwd
            with pytest.raises(IOError):
                with sftp.cd('not-there'):
                    pass
            assert home == sftp.pwd


def test_cd_local():
    '''test sftpretty.cd on local directories'''
    original = Path.cwd().as_posix()
    with cd('docs'):
        assert Path.cwd().as_posix() == Path(original).joinpath('docs').as_posix()
    assert Path.cwd().as_posix() == original


def test_cd_local_bad():
    '''test sftpretty.cd on non-existing local directory'''
    with pytest.raises(OSError):
        with cd('not-there'):
            pass
