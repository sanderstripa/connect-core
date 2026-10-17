"""Build immutable Linux server packages on a development/CI machine, not a VPS."""
import argparse, gzip, hashlib, io, json, os, pathlib, subprocess, tarfile, tempfile

p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--arch',choices=['amd64','arm64','all'],default='all');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
for arch in (['amd64','arm64'] if a.arch=='all' else [a.arch]):
    with tempfile.TemporaryDirectory(prefix='connect-package-') as td:
        stage=pathlib.Path(td);(stage/'bin').mkdir();(stage/'scripts').mkdir();(stage/'tmp').mkdir()
        env=dict(os.environ,GOOS='linux',GOARCH=arch,CGO_ENABLED='0',GOTMPDIR=str(stage/'tmp'))
        for name in ['connect-core','connect-control','connect-ui','connect-cert']:
            subprocess.run(['go','build','-trimpath','-ldflags','-X github.com/sanderstripa/connect-core/internal/management.BuildRevision='+revision,'-o',str(stage/'bin'/name),'./cmd/'+name],cwd=root,env=env,check=True)
        for name in ['connect-install.py','connect-vps-network.py']:
            (stage/'scripts'/name).write_bytes((root/'scripts'/name).read_bytes())
        (stage/'third_party'/'licenses').mkdir(parents=True)
        for license in (root/'third_party'/'licenses').glob('*.txt'):
            (stage/'third_party'/'licenses'/license.name).write_bytes(license.read_bytes())
        (stage/'THIRD-PARTY-NOTICES.md').write_bytes((root/'THIRD-PARTY-NOTICES.md').read_bytes())
        files={f.relative_to(stage).as_posix():hashlib.sha256(f.read_bytes()).hexdigest() for parent in ['bin','scripts','third_party/licenses'] for f in sorted((stage/parent).iterdir())}
        files['THIRD-PARTY-NOTICES.md']=hashlib.sha256((stage/'THIRD-PARTY-NOTICES.md').read_bytes()).hexdigest()
        (stage/'package.json').write_text(json.dumps({'schema':1,'revision':revision,'arch':arch,'files':files},sort_keys=True),encoding='utf-8')
        archive=out/f'ConnectCore-Linux-{arch}-{revision[:7]}.tar.gz'
        with archive.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w') as tar:
            for name in sorted([*files,'package.json']):
                data=(stage/name).read_bytes();info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o755 if name.startswith('bin/') else 0o644;tar.addfile(info,io.BytesIO(data))
        print(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name,flush=True)
