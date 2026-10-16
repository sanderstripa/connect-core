"""Package the supplied PNG as a Windows ICO without redrawing its artwork."""
import argparse, hashlib, json, pathlib
from PIL import Image
p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('destination');a=p.parse_args()
src=pathlib.Path(a.source);out=pathlib.Path(a.destination)
with Image.open(src) as image:
    if image.width != image.height: raise SystemExit('Square source artwork required')
    sizes=[(n,n) for n in (16,20,24,32,40,48,64,128,256)]
    image.convert('RGBA').save(out,format='ICO',sizes=sizes)
with Image.open(out) as icon:
    if icon.ico.sizes()!=set(sizes): raise SystemExit('Missing icon frames')
print(json.dumps({'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'ico_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'sizes':sizes}))
