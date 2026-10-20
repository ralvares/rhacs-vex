#!/usr/bin/env python3
"""Evidence ⇄ one Parquet file (format `vextriage-evidence-tar-v1`), lossless.

    python3 tests/evidence_parquet.py pack   evidence/  evidence.parquet
    python3 tests/evidence_parquet.py unpack evidence.parquet  <dir>

The file holds the exact tar stream of the directory, zstd-compressed with a
long window (grype repeats each package and the SBOM in every match and run;
a 2.7 GB evidence directory packs to ~28 MB), split into `payload` rows, plus
one `entry` row per tar member (path, size, sha256, tar header) so the content
can be listed without unpacking.  The manifest in the schema metadata carries
the sha256 of the tar and of the payload; unpack verifies both.

Needs `pip install zstandard pyarrow`.
"""
import hashlib
import io
import json
import os
import sys
import tarfile

import pyarrow as pa
import pyarrow.parquet as pq

FORMAT = 'vextriage-evidence-tar-v1'
BLOCK = 1 << 20
WINDOW_LOG = 27            # 128 MB long-range window: repeats across files fold
MAX_WINDOW = 1 << 31       # what a reader accepts (other packers may use more)


class _Sink(io.RawIOBase):
    """Collects compressed bytes in BLOCK-sized chunks, hashing as it goes."""

    def __init__(self):
        self.blocks, self.buf, self.sha = [], bytearray(), hashlib.sha256()

    def writable(self):
        return True

    def write(self, b):
        self.sha.update(b)
        self.buf += b
        while len(self.buf) >= BLOCK:
            self.blocks.append(bytes(self.buf[:BLOCK]))
            del self.buf[:BLOCK]
        return len(b)

    def flush_all(self):
        if self.buf:
            self.blocks.append(bytes(self.buf))
            self.buf = bytearray()


class _Hashing(io.RawIOBase):
    """Pass-through writer that hashes and counts the tar stream."""

    def __init__(self, inner):
        self.inner, self.sha, self.n = inner, hashlib.sha256(), 0

    def writable(self):
        return True

    def write(self, b):
        self.sha.update(b)
        self.n += len(b)
        return self.inner.write(b)


def _file_sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for blk in iter(lambda: fh.read(BLOCK), b''):
            h.update(blk)
    return h.hexdigest()


def pack(src: str, dest: str) -> None:
    import zstandard
    sink = _Sink()
    params = zstandard.ZstdCompressionParameters.from_level(
        19, window_log=WINDOW_LOG, enable_ldm=True)
    zw = zstandard.ZstdCompressor(compression_params=params).stream_writer(sink, closefd=False)
    tar_out = _Hashing(zw)
    entries = []
    with tarfile.open(fileobj=tar_out, mode='w|', format=tarfile.PAX_FORMAT) as tar:
        base = os.path.dirname(os.path.abspath(src))
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for name in [None] + sorted(files):
                path = root if name is None else os.path.join(root, name)
                if name and name.startswith('._'):
                    continue
                info = tar.gettarinfo(path, os.path.relpath(os.path.abspath(path), base))
                if info.isreg():
                    with open(path, 'rb') as fh:
                        tar.addfile(info, fh)
                else:
                    tar.addfile(info)
                entries.append({'path': info.name, 'size': info.size,
                                'sha256': _file_sha(path) if info.isreg() else None,
                                'metadata_json': json.dumps(info.get_info(), default=str)})
    zw.flush(zstandard.FLUSH_FRAME)
    sink.flush_all()
    manifest = {'format': FORMAT, 'source': os.path.basename(os.path.abspath(src)),
                'tar_sha256': tar_out.sha.hexdigest(), 'tar_bytes': tar_out.n,
                'payload_sha256': sink.sha.hexdigest(),
                'payload_bytes': sum(len(b) for b in sink.blocks),
                'payload_codec': 'zstd', 'payload_blocks': len(sink.blocks),
                'entries': len(entries), 'files': sum(1 for e in entries if e['sha256']),
                'file_bytes': sum(e['size'] for e in entries if e['sha256']),
                'encoding': 'zstd; exact tar stream', 'lossless': True}
    rows = [{'kind': 'entry', 'sequence': i, 'data': None, **e} for i, e in enumerate(entries)]
    rows += [{'kind': 'payload', 'sequence': i, 'path': None, 'size': len(b), 'sha256': None,
              'metadata_json': None, 'data': b} for i, b in enumerate(sink.blocks)]
    schema = pa.schema([('kind', pa.string()), ('sequence', pa.int64()), ('path', pa.string()),
                        ('size', pa.int64()), ('sha256', pa.string()),
                        ('metadata_json', pa.string()), ('data', pa.binary())],
                       metadata={'evidence_format': FORMAT,
                                 'evidence_manifest': json.dumps(manifest)})
    pq.write_table(pa.Table.from_pylist(rows, schema=schema), dest, compression='none')
    print(f"{dest}: {manifest['files']} files, {manifest['tar_bytes'] / 1e6:,.0f} MB → "
          f"{os.path.getsize(dest) / 1e6:,.1f} MB")


def unpack(src: str, out: str) -> None:
    import zstandard
    f = pq.ParquetFile(src)
    manifest = json.loads(f.schema_arrow.metadata[b'evidence_manifest'])
    if manifest.get('format') != FORMAT:
        raise SystemExit(f'not a {FORMAT} file')
    t = pq.read_table(src, columns=['kind', 'sequence', 'data']).to_pandas()
    payload = b''.join(t[t.kind == 'payload'].sort_values('sequence').data)
    if hashlib.sha256(payload).hexdigest() != manifest['payload_sha256']:
        raise SystemExit('payload checksum mismatch')

    class Reader(io.RawIOBase):
        def __init__(self, r):
            self.r, self.sha = r, hashlib.sha256()

        def readable(self):
            return True

        def readinto(self, b):
            d = self.r.read(len(b))
            b[:len(d)] = d
            self.sha.update(d)
            return len(d)

    rd = Reader(zstandard.ZstdDecompressor(max_window_size=MAX_WINDOW)
                .stream_reader(io.BytesIO(payload), read_across_frames=True))
    with tarfile.open(fileobj=io.BufferedReader(rd, BLOCK), mode='r|') as tar:
        tar.extractall(out, filter='data')
    while rd.read(BLOCK):
        pass
    if rd.sha.hexdigest() != manifest['tar_sha256']:
        raise SystemExit('tar checksum mismatch')
    print(f"{out}: {manifest['files']} files, checksums verified")


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] not in ('pack', 'unpack'):
        raise SystemExit(__doc__)
    (pack if sys.argv[1] == 'pack' else unpack)(sys.argv[2], sys.argv[3])
