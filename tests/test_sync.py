"""The mirror (one SQLite file of gzipped documents, stamped with Red Hat's change time)
and the index built from it."""
import json
import os

from conftest import csaf, rhel_image, rpm, rpm_pkg

from vextriage.index import Index
from vextriage.sync import Mirror
from vextriage.triage import triage


def test_old_directory_mirror_is_imported_and_only_changes_are_reindexed(tmp_path):
    vex = tmp_path / 'vex'                              # a mirror written before the SQLite one
    vex.mkdir()
    (vex / 'CVE-2099-0001.json').write_text(json.dumps(
        csaf('CVE-2099-0001', [('known_affected', 'red_hat_enterprise_linux_9', rpm('zlib'))])))
    os.utime(vex / 'CVE-2099-0001.json', (1700000000, 1700000000))
    mirror = Mirror(str(tmp_path / 'vex.sqlite'))
    assert mirror.import_dir(str(vex), lambda *_: None) == 1
    assert mirror.stamps() == {'CVE-2099-0001': 1700000000.0}
    assert mirror.load('CVE-2099-0001')['vulnerabilities'][0]['cve'] == 'CVE-2099-0001'

    ix = Index(str(tmp_path / 'index.sqlite'))
    assert ix.update(mirror, workers=1)['read'] == 1
    assert ix.doc('CVE-2099-0001').statements[0].comp.name == 'zlib'
    assert ix.update(mirror, workers=1)['read'] == 0            # nothing changed
    mirror.put([('CVE-2099-0002', json.dumps(csaf('CVE-2099-0002', [
        ('fixed', 'BaseOS-9.4.0.Z.EUS', rpm('tar', '1.34-7.el9_4'))])).encode(), 1700000100.0)])
    mirror.delete(['CVE-2099-0001'])
    assert ix.update(mirror, workers=1) | {'seconds': 0} == {'read': 1, 'removed': 1, 'documents': 1, 'seconds': 0}
    assert ix.doc('CVE-2099-0001') is None


def test_the_scan_reads_only_what_concerns_the_image(index):
    ix = index(csaf('CVE-2099-0001', [('known_affected', 'red_hat_enterprise_linux_9', rpm('zlib')),
                                      ('known_affected', 'red_hat_enterprise_linux_9', rpm('kernel'))]),
               csaf('CVE-2099-0002', [('known_affected', 'red_hat_enterprise_linux_9', rpm('kernel'))]))
    img = rhel_image()
    img.packages.append(rpm_pkg('zlib', '1.2.11-40.el9'))
    _, rows = triage(img, ix)
    assert [(r.finding.cve, r.finding.package.name, r.verdict.status) for r in rows] == \
        [('CVE-2099-0001', 'zlib', 'affected')]


def test_an_index_of_an_older_format_is_rebuilt(tmp_path):
    import sqlite3
    old = sqlite3.connect(str(tmp_path / 'index.sqlite'))      # format 4: documents as blobs
    old.executescript("CREATE TABLE doc (id INTEGER PRIMARY KEY, cve TEXT UNIQUE, mtime REAL, blob BLOB);"
                      "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); INSERT INTO meta VALUES ('version', '4');")
    old.commit()
    old.close()
    mirror = Mirror(str(tmp_path / 'vex.sqlite'))
    mirror.put([('CVE-2099-0001', json.dumps(csaf('CVE-2099-0001', [
        ('known_affected', 'red_hat_enterprise_linux_9', rpm('zlib'))])).encode(), 1700000000.0)])
    ix = Index(str(tmp_path / 'index.sqlite'))
    assert ix.update(mirror, workers=1)['documents'] == 1
    assert ix.doc('CVE-2099-0001').statements[0].comp.name == 'zlib'
