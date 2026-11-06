import sys
import binaryninja as bn
bv = bn.load(sys.argv[1])
print("view_type:", bv.view_type)
for attr in ("arch","file","original_view_type","start","entry_point","platform","sections"):
    try:
        v = getattr(bv, attr)
        print("  bv.%-18s = %r" % (attr, v if attr != "file" else type(v).__name__))
    except Exception as e:
        print("  bv.%-18s ! %s" % (attr, e))
try:
    print("bv.file.view_types:", [str(x) for x in bv.file.view_types])
except Exception as e:
    print("  file.view_types !", e)
print("arch module attrs:", [a for a in dir(bn) if "arch" in a.lower()][:12])
bv.file.close()
