#!/usr/bin/env python3
"""Bind final source, all retained artifact candidates and completed raw evidence."""
from pathlib import Path
import datetime, hashlib, json, os, shutil, subprocess
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence/final-source'
assert not OUT.exists(), 'Never overwrite an earlier freeze.'
def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()
sources = []
for directory, dirs, names in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in ['evidence', 'build', '.gradle', '.kotlin', '__pycache__', '.git']]
    for name in names:
        p = Path(directory) / name
        if name == 'local.properties' or name.endswith('.log'): continue
        rel = p.relative_to(ROOT)
        dest = OUT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if os.uname().sysname == 'Darwin': subprocess.run(['cp', '-c', str(p), str(dest)], check=True)
        else: shutil.copy2(p, dest)
        assert sha(p) == sha(dest)
        sources.append({'path': str(rel), 'snapshot': str(dest.relative_to(ROOT)), 'sha256': sha(p)})
artifacts = []
for manifest in sorted((ROOT / 'evidence').glob('*/manifest.json')):
    record = json.loads(manifest.read_text())
    if record.get('status') != 'SOURCE_AND_ARTIFACT_IDENTITY_ONLY': continue
    for rel, expected in record['sources'].items(): assert sha(manifest.parent / 'source' / rel) == expected
    for rel, expected in record['artifacts'].items():
        assert sha(ROOT / rel) == expected
        artifacts.append({'path': rel, 'sha256': expected, 'scope': record.get('kind', 'runtime'), 'manifest': str(manifest.relative_to(ROOT))})
evidence = []
for p in sorted((ROOT / 'evidence').rglob('*')):
    if p.is_file() and 'final-source' not in p.parts and p.name != 'runtime-freeze.json':
        evidence.append({'path': str(p.relative_to(ROOT)), 'sha256': sha(p)})
record = {'status': 'FROZEN_FOR_INDEPENDENT_REVIEW', 'date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'sources': sources, 'artifacts': artifacts, 'evidence_files': evidence,
          'scope': 'Final Common Goods trust-boundaries source and retained attempts. runtime-build5 owns the final APK implementation, Android HTTP/storage campaign and final native capture. Initial core failure, Chrome first-use interruption and superseded debug manifest/captures remain labeled. Credentials never enter typed service reports. Correctness, selected cross-UID probes, native pixels and publication review are separate evidence; no production identity, all-device security or penetration-test certification is claimed.'}
(ROOT / 'evidence/runtime-freeze.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'sources': len(sources), 'artifacts': len(artifacts), 'evidence_files': len(evidence)}))
