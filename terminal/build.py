"""Build one uploadable installer; never embeds VPS addresses or credentials."""
import base64
import hashlib
import io
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parent
out = root.parent/'dist'
out.mkdir(exist_ok=True)
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
    for name in ['nodelite.py', 'runtime.py', 'protocols.py']:
        data = (root/name).read_bytes().replace(b'\r\n', b'\n')
        item = tarfile.TarInfo(name)
        item.size, item.mode, item.mtime = len(data), 0o600, 0
        archive.addfile(item, io.BytesIO(data))
payload = buffer.getvalue()
digest = hashlib.sha256(payload).hexdigest()
script = (root/'install.sh').read_text(encoding='utf-8')
script = script.replace('__PAYLOAD__', "cat > \"$work/payload.b64\" <<'PAYLOAD'\n"+
                        base64.encodebytes(payload).decode()+"PAYLOAD")
script = script.replace('!= PAYLOAD_SHA256:', '!= '+repr(digest)+':')
for stale in ('subprogress-lite.run', 'subprogress-lite.run.sha256'):
    (out/stale).unlink(missing_ok=True)
target = out/'nodelite.run'
target.write_bytes(script.replace('\r\n', '\n').encode())
(out/'nodelite.run.sha256').write_text(hashlib.sha256(target.read_bytes()).hexdigest()+
                                       '  nodelite.run\n', encoding='ascii')
print(str(target)+' ('+str(target.stat().st_size)+' bytes)')
