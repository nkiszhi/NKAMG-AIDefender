"""Fail-closed, JSON-only MalGraph input contract. Never execute input samples."""
import collections, hashlib, json, math, pathlib, re
ROLES=('train','model_val','calibration','test');RATIOS=(.60,.15,.10,.15);SHA=re.compile('[a-f0-9]{64}')
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
def file_sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
 return h.hexdigest()
def atomic_json(p,value):
 p=pathlib.Path(p);p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_suffix(p.suffix+'.tmp');tmp.write_text(json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False,indent=2)+'\n',encoding='utf8');tmp.replace(p)
def validate_graph(g,expected_sha):
 if not isinstance(g,dict) or g.get('hash')!=expected_sha:raise ValueError('graph/sample SHA256 mismatch')
 local=g.get('acfg_list');names=g.get('function_names');n=g.get('function_number')
 if not isinstance(local,list) or not local or not isinstance(names,list) or type(n) is not int or n!=len(names) or n<len(local):raise ValueError('invalid/nonempty local CFG and FCG counts')
 if any(not isinstance(v,str) or not v for v in names):raise ValueError('invalid function name')
 def edges(e,nodes):
  if not isinstance(e,list) or len(e)!=2 or any(not isinstance(x,list) for x in e) or len(e[0])!=len(e[1]):raise ValueError('edge tensor must have shape 2 x E')
  if any(type(x) is not int or not 0<=x<nodes for row in e for x in row):raise ValueError('graph edge out of bounds')
 for cfg in local:
  x=cfg.get('block_features');blocks=cfg.get('block_number')
  if not isinstance(x,list) or not x or type(blocks) is not int or blocks!=len(x):raise ValueError('zero/misaligned CFG blocks')
  if any(not isinstance(row,list) or len(row)!=11 or any(type(v) not in (int,float) or not math.isfinite(v) or v<0 for v in row) for row in x):raise ValueError('CFG requires 11 finite nonnegative actual features')
  if sum(row[8] for row in x)<=0:raise ValueError('CFG has no actual instructions')
  edges(cfg.get('block_edges'),blocks)
 edges(g.get('function_edges'),n)
 return g

def make_plan(selection,output,seed=20261116):
 selection=pathlib.Path(selection).resolve();rows=[json.loads(l) for l in selection.read_text(encoding='utf8').splitlines() if l.strip()]
 seen=set();groups=collections.defaultdict(list);counts=collections.Counter()
 for original in rows:
  r=dict(original);h=r.get('sha256');label=r.get('label');typ=r.get('pe_type')
  if not isinstance(h,str) or not SHA.fullmatch(h) or h in seen or label not in ('benign','malicious') or typ not in ('dll32','dll64','exe32','exe64') or r.get('selection_status')!='final_quota_met':raise ValueError('require complete verified balanced selection, not provisional')
  seen.add(h);counts[label,typ]+=1
  ss=r.get('ssdeep','');valid_ss=bool(re.fullmatch(r'[1-9][0-9]*:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+',ss))
  gid='ssdeep-exact:'+digest(ss) if valid_ss else 'sha256:'+h
  r.update(sample_id=h,group_id=gid,group_rule='source_ssdeep_exact' if valid_ss else 'sha256_only',label_value=int(label=='malicious'));groups[gid].append(r)
 if len(counts)!=8 or len(set(counts.values()))!=1 or not rows:raise ValueError('eight equal nonempty strata required')
 totals=collections.Counter((r['label'],r['pe_type']) for r in rows);used={role:collections.Counter() for role in ROLES};assigned=[]
 for gid,rs in sorted(groups.items(),key=lambda kv:(-len(kv[1]),digest([seed,kv[0]]))):
  if len({r['label'] for r in rs})!=1:raise ValueError('exact ssdeep group has conflicting labels; manual review required')
  gc=collections.Counter((r['label'],r['pe_type']) for r in rs)
  def cost(idx):
   return sum(((used[ROLES[idx]][key]+n)**2-used[ROLES[idx]][key]**2)/(totals[key]*RATIOS[idx]) for key,n in gc.items())
  role=ROLES[min(range(4),key=cost)]
  for r in rs:r['split']=role;assigned.append(r);used[role][r['label'],r['pe_type']]+=1
 for role in ROLES:
  if any(sum(n for (lab,typ),n in used[role].items() if lab==label)==0 for label in ('benign','malicious')):raise ValueError('each role must contain both labels')
 # Contents, rather than fabricated temporal months, form the shared explicit role contract.
 doc={'schema':'balanced-pe-four-role-v1','selection_path':str(selection),'selection_sha256':file_sha(selection),'seed':seed,'partition_method':'stratified_exact-ssdeep-grouped_random_not_temporal','ratios':dict(zip(ROLES,RATIOS)),'group_count':len(groups),'counts':{role:{lab:sum(n for (label,_),n in used[role].items() if label==lab) for lab in ('benign','malicious')} for role in ROLES},'samples':sorted(assigned,key=lambda r:r['sample_id']),'test_accessed':False,'deployable':False,'limitations':['directory_labels_not_independently_reviewed','exact_ssdeep_not_family_or_near_duplicate_isolation','collection_and_database_dates_are_not_first_seen']}
 doc['plan_fingerprint']=digest(doc);atomic_json(output,doc);return doc

def load_plan(p):
 p=pathlib.Path(p);d=json.loads(p.read_text(encoding='utf8'));f=d.pop('plan_fingerprint',None)
 if d.get('schema')!='balanced-pe-four-role-v1' or f!=digest(d):raise ValueError('split plan fingerprint mismatch')
 d['plan_fingerprint']=f
 if file_sha(d['selection_path'])!=d['selection_sha256']:raise ValueError('source selection changed')
 originals={r['sha256']:r for r in (json.loads(l) for l in pathlib.Path(d['selection_path']).read_text(encoding='utf8').splitlines() if l.strip())}
 seen=set();groups={};actual={r:collections.Counter() for r in ROLES}
 for r in d['samples']:
  sid=r['sample_id'];role=r['split'];gid=r['group_id']
  original=originals.get(sid)
  if original is None or any(r.get(k)!=v for k,v in original.items()):raise ValueError('split sample differs from verified selection')
  ss=r.get('ssdeep','');valid_ss=bool(re.fullmatch(r'[1-9][0-9]*:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+',ss));expected_gid='ssdeep-exact:'+digest(ss) if valid_ss else 'sha256:'+sid
  if gid!=expected_gid or type(r.get('label_value')) is not int:raise ValueError('invalid grouping or label type')
  if sid!=r['sha256'] or not SHA.fullmatch(sid) or sid in seen or role not in ROLES or r['label_value']!=int(r['label']=='malicious'):raise ValueError('invalid or duplicate split identity')
  if gid in groups and groups[gid]!=(role,r['label']):raise ValueError('cross-role/label group leak')
  seen.add(sid);groups[gid]=(role,r['label']);actual[role][r['label']]+=1
 if seen!=set(originals):raise ValueError('split does not cover complete selection')
 if {r:dict(actual[r]) for r in ROLES}!=d['counts']:raise ValueError('split counts differ')
 return d


def runtime_contract(analysis_timeout=120,hard_timeout=180):
 import importlib.metadata,platform
 if type(analysis_timeout) is not int or analysis_timeout<30 or type(hard_timeout) is not int or hard_timeout<=analysis_timeout:raise ValueError('require native >=30s and larger positive hard timeout')
 project=pathlib.Path(__file__).resolve().parents[1]
 source_names=['train/retrain_malgraph_contract.py','train/retrain_malgraph_worker.py','feature_extraction/smda_extract.py','feature_extraction/hashing.py','insn_categories.py']
 d={'schema':'malgraph-smda-topology-v1','packages':{n:importlib.metadata.version(n) for n in ['numpy','smda','capstone','lief','demangle','dncil','dnfile','purepdb','pefile']},'python':platform.python_version(),'backend':'intel','machine_allowlist':[0x14c,0x8664],'api_name_style':'raw','analysis_timeout':analysis_timeout,'hard_timeout':hard_timeout,'block_feature_dim':11,'max_blocks':1000000,'sources':{n:file_sha(project/n) for n in source_names},'edge_semantics':'native_local_call_xrefs_and_direct_API_call_references; no_inferred_graph'}
 d['fingerprint']=digest(d);return d

def check_runtime_contract(d):
 if runtime_contract(d['analysis_timeout'],d['hard_timeout'])!=d:raise ValueError('SMDA graph extractor runtime/source versions changed')
