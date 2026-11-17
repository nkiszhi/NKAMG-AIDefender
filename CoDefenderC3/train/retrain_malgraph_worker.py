"""Single-PE static SMDA worker. Hard-killed by parent; never imports torch or executes PE."""
import argparse,gzip,importlib.util,json,os,pathlib,struct,sys,types
from retrain_malgraph_contract import atomic_json,check_runtime_contract,digest,file_sha,validate_graph

def require_intel_pe(sample):
 with pathlib.Path(sample).open('rb') as f:
  dos=f.read(64)
  if len(dos)!=64 or dos[:2]!=b'MZ':raise ValueError('invalid PE DOS header')
  offset=struct.unpack_from('<I',dos,60)[0];f.seek(offset);coff=f.read(24);opt=f.read(2)
 if len(coff)!=24 or coff[:4]!=b'PE\0\0' or len(opt)!=2:raise ValueError('invalid PE signature/optional header')
 machine=struct.unpack_from('<H',coff,4)[0];magic=struct.unpack('<H',opt)[0]
 if (machine,magic) not in [(0x14c,0x10b),(0x8664,0x20b)]:raise ValueError('PE architecture unsupported by pinned intel backend: 0x%04x'%machine)
 return machine

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',required=True,type=pathlib.Path);args=p.parse_args();request=json.loads(args.request.read_text(encoding='utf8'));reply={'status':'error','sample_id':request['sample_id'],'contract_fingerprint':request['contract']['fingerprint']}
 try:
  c=request['contract'];check_runtime_contract(c);sample=pathlib.Path(request['source_path']);before=sample.stat()
  if sample.is_symlink() or [before.st_size,before.st_mtime_ns]!=[request['size_bytes'],request['mtime_ns']]:raise ValueError('source stamp changed or symlink')
  require_intel_pe(sample)
  project=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(project));featdir=project/'feature_extraction';package=types.ModuleType('feature_extraction');package.__path__=[str(featdir)];sys.modules['feature_extraction']=package
  os.environ['CODEFENDER_SMDA_API_NAME_STYLE']=c['api_name_style'];os.environ['CODEFENDER_SMDA_BACKEND']=c['backend']
  spec=importlib.util.spec_from_file_location('feature_extraction.smda_extract',featdir/'smda_extract.py');mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
  class StrictSmdaGraphExtractor(mod.SmdaExtractor):
   @staticmethod
   def _call_edges(func,local_index,api_index):
    # SMDA getCodeOutrefs contains only resolved in-binary xrefs, not imported APIs.
    edges=set();apirefs=getattr(func,'apirefs',{}) or {}
    for block in (getattr(func,'blocks',{}) or {}).values():
     for ins in block:
      if (ins.mnemonic or '').lower()=='call' and ins.offset in apirefs:
       name=mod._api_name(apirefs[ins.offset])
       if name in api_index:edges.add((api_index[name],False))
    for xr in func.getCodeOutrefs():
     src=getattr(xr,'from_instruction',None);callee=getattr(xr,'to_function',None)
     if src is not None and (src.mnemonic or '').lower()=='call' and callee is not None:
      offset=getattr(callee,'offset',None)
      if offset in local_index:edges.add((local_index[offset],offset==getattr(func,'offset',None)))
    return sorted(edges)
  ex=StrictSmdaGraphExtractor(timeout=c['analysis_timeout'],backend=c['backend']);report=ex._analyze(str(sample));status=getattr(report,'status',None)
  if status!='ok':raise ValueError('SMDA native status is '+str(status))
  funcs=list(report.getFunctions());blocks=sum(len(getattr(f,'blocks',{}) or {}) for f in funcs)
  if not funcs:raise ValueError('SMDA completed without resolvable functions; no dummy graph allowed')
  if blocks>c['max_blocks']:raise ValueError('graph resource limit exceeded')
  graph=validate_graph(ex.extract_cfg_and_fcg(str(sample),{}),request['sample_id'])
  if file_sha(sample)!=request['sample_id']:raise ValueError('source SHA256 mismatch')
  after=sample.stat()
  if [after.st_size,after.st_mtime_ns]!=[before.st_size,before.st_mtime_ns]:raise ValueError('source changed during native extraction')
  if 'torch' in sys.modules:raise ValueError('feature worker imported forbidden training runtime')
  payload={'schema':'malgraph-static-cache-v1','sample_id':request['sample_id'],'contract_fingerprint':c['fingerprint'],'graph_digest':digest(graph),'graph':graph}
  output=pathlib.Path(request['output']);tmp=output.with_suffix(output.suffix+'.tmp');tmp.parent.mkdir(parents=True,exist_ok=True)
  with tmp.open('wb') as f:
   with gzip.GzipFile(fileobj=f,mode='wb',mtime=0) as gz:gz.write(json.dumps(payload,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
  tmp.replace(output);reply.update(status='ok',cache_sha256=file_sha(output),local_functions=len(graph['acfg_list']),external_functions=len(graph['function_names'])-len(graph['acfg_list']),blocks=blocks,fcg_edges=len(graph['function_edges'][0]),cfg_edges=sum(len(x['block_edges'][0]) for x in graph['acfg_list']))
 except Exception as e:reply['error']=type(e).__name__+': '+str(e)
 atomic_json(request['response'],reply);print(json.dumps(reply),flush=True);return 0 if reply['status']=='ok' else 1
if __name__=='__main__':raise SystemExit(main())
