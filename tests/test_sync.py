"""The mirror: gzipped documents stamped with Red Hat's change time, read by the index."""
import json
import os

from conftest import csaf, rpm

from vextriage import sync
from vextriage.index import Index


def test_mirror_is_gzipped_and_old_plain_files_are_compressed_in_place(tmp_path):
    vex = tmp_path / 'vex'
    vex.mkdir()
    doc = csaf('CVE-2099-0001', [('known_affected', 'red_hat_enterprise_linux_9', rpm('zlib'))])
    sync._write(str(vex / 'CVE-2099-0001.json.gz'), json.dumps(doc).encode(), 1700000000)
    plain = vex / 'CVE-2099-0002.json'                  # a mirror written before gzip
    plain.write_text(json.dumps(csaf('CVE-2099-0002', [('fixed', 'red_hat_enterprise_linux_9', rpm('tar'))])))
    os.utime(plain, (1700000100, 1700000100))
    assert set(sync.files(str(vex))) == {'CVE-2099-0001', 'CVE-2099-0002'}

    ix = Index(str(tmp_path / 'index.sqlite'))
    assert ix.update(str(vex), workers=1)['read'] == 2
    assert ix.doc('CVE-2099-0001').statements[0].comp.name == 'zlib'

    assert sync._compress_plain(str(vex), 1, lambda *_: None) == 1
    assert sorted(os.listdir(vex)) == ['CVE-2099-0001.json.gz', 'CVE-2099-0002.json.gz']
    assert os.path.getmtime(vex / 'CVE-2099-0002.json.gz') == 1700000100
    assert sync.load(str(vex / 'CVE-2099-0002.json.gz'))['vulnerabilities'][0]['cve'] == 'CVE-2099-0002'
    # same change time: the index has nothing to re-read
    assert ix.update(str(vex), workers=1)['read'] == 0
