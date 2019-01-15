'''test sftpretty.get_d'''

from common import VFS, conn
from pathlib import Path
from sftpretty import Connection
from tempfile import mkdtemp


def test_get_d(sftpserver):
    '''test the get_d for remotepath is pwd '.' '''
    with sftpserver.serve_content(VFS):
        with Connection(**conn(sftpserver)) as sftp:
            sftp.cwd('pub')
            localpath = mkdtemp()
            sftp.get_d('.', localpath)

            checks = [(['', ], ['make.txt', ]), ]
            for pth, fls in checks:
                assert sorted(Path(Path(localpath).joinpath(*pth).as_posix()).iterdir()) == fls

            # cleanup local
            Path(localpath).rmdir()


def test_get_d_pathed(sftpserver):
    '''test the get_d for localpath, starting deeper then pwd '''
    with sftpserver.serve_content(VFS):
        with Connection(**conn(sftpserver)) as sftp:
            sftp.cwd('pub')
            localpath = mkdtemp()
            sftp.get_d('foo1', localpath)

            chex = [(['', ],
                     ['foo1.txt', 'image01.jpg']), ]
            for pth, fls in chex:
                assert sorted(Path(Path(localpath).joinpath(*pth).as_posix()).iterdir()) == fls

            # cleanup local
            Path(localpath).rmdir()
