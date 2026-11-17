"""Dedicated SMDA/MalGraph research retraining: real CFG/FCG, fixed train-only vocabulary.
Only explicitly authorized audited applicability exclusions; no production overwrite or test-time tuning.
"""
import argparse,collections,concurrent.futures,gzip,json,logging,os,pathlib,random,shutil,subprocess,sys,tempfile,time
from retrain_malgraph_coverage import policy,freeze_policy,build_manifest,save_eligibility,load_eligibility,population_metrics
from retrain_malgraph_contract import ROLES,atomic_json,check_runtime_contract,digest,file_sha,load_plan,make_plan,runtime_contract,validate_graph
PROJECT=pathlib.Path(__file__).resolve().parents[1]
PARAMS=dict(gnn_type='graphsage',pool_type='global_mean_pool',acfg_init_dims=11,cfg_filters='64-64',fcg_filters='64-64',number_classes=1,dropout_rate=.2,ablation_models='none')

def read_graph(path,sid,contract):
 with gzip.open(path,'rb') as f:b=f.read(256*1024*1024+1)
 if len(b)>256*1024*1024:raise ValueError('graph cache exceeds JSON resource budget')
 d=json.loads(b)
 if d.get('schema')!='malgraph-static-cache-v1' or d.get('sample_id')!=sid or d.get('contract_fingerprint')!=contract['fingerprint'] or d.get('graph_digest')!=digest(d.get('graph')):raise ValueError('cache identity/digest mismatch')
 return validate_graph(d['graph'],sid)

def cache_file(work,contract,sid):
 p=(pathlib.Path(work)/'graphs'/contract['fingerprint']/sid[:2]/(sid+'.json.gz')).resolve()
 prefix='\\\\?\\'
 if os.name=='nt' and not str(p).startswith(prefix):
  text=str(p);p=pathlib.Path(prefix+text) if not text.startswith('\\\\') else pathlib.Path(prefix+'UNC\\'+text[2:])
 return p

def extract_one(r,c,work,package_paths,verify_source_sha=False):
 sid=r['sample_id'];target=cache_file(work,c,sid);reply=dict(sample_id=sid,split=r['split'],status='error',cache_path=str(target));sample=pathlib.Path(r['source_path'])
 try:
  s=sample.stat()
  if sample.is_symlink() or [s.st_size,s.st_mtime_ns]!=[r['size_bytes'],r['mtime_ns']]:raise ValueError('source stamp changed; reselect and reverify')
  if verify_source_sha and file_sha(sample)!=sid:raise ValueError('source SHA256 mismatch before sample exclusion')
  if target.exists():
   g=read_graph(target,sid,c);return dict(reply,status='ok',cached=True,cache_sha256=file_sha(target),local_functions=len(g['acfg_list']),blocks=sum(len(v['block_features']) for v in g['acfg_list']),fcg_edges=len(g['function_edges'][0]))
  with tempfile.TemporaryDirectory(prefix='worker-',dir=pathlib.Path(work)) as td:
   td=pathlib.Path(td);response=td/'response.json';request=td/'request.json';atomic_json(request,dict(sample_id=sid,source_path=str(sample),size_bytes=r['size_bytes'],mtime_ns=r['mtime_ns'],contract=c,output=str(target),response=str(response)))
   env={k:v for k,v in os.environ.items() if not k.startswith(('CODEFENDER_','BN_')) and k not in ('PYTHONPATH','PYTHONHOME')};env.update(PYTHONPATH=os.pathsep.join(str(pathlib.Path(p).resolve()) for p in package_paths),PYTHONNOUSERSITE='1',PYTHONIOENCODING='utf-8',PYTHONHASHSEED='0')
   try:run=subprocess.run([sys.executable,'-X','utf8',str(pathlib.Path(__file__).with_name('retrain_malgraph_worker.py')),'--request',str(request)],cwd=td,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=c['hard_timeout'])
   except subprocess.TimeoutExpired:return dict(reply,status='timeout',error='native worker hard-killed at timeout')
   if not response.exists():raise ValueError('worker failed without response: '+run.stderr.decode('utf8',errors='replace')[-2000:])
   d=json.loads(response.read_text(encoding='utf8'))
   if d.get('sample_id')!=sid or d.get('contract_fingerprint')!=c['fingerprint']:raise ValueError('worker response identity mismatch')
   reply.update(d)
   if d['status']=='ok':
    if run.returncode or file_sha(target)!=d['cache_sha256']:raise ValueError('worker returncode/cache digest mismatch')
    read_graph(target,sid,c)
   return reply
 except Exception as e:return dict(reply,status='error',error=type(e).__name__+': '+str(e))

def ensure_cache(rows,c,work,package_paths,workers,report_name='cache_report.json',coverage_policy=None,plan_fingerprint=None,eligibility_name=None):
 work=pathlib.Path(work);work.mkdir(parents=True,exist_ok=True);check_runtime_contract(c);records=[];begin=time.time()
 with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
  futures={pool.submit(extract_one,r,c,work,package_paths,True):r for r in rows} if coverage_policy and coverage_policy['mode']=='audited_partial' else {pool.submit(extract_one,r,c,work,package_paths):r for r in rows}
  for future in concurrent.futures.as_completed(futures):
   records.append(future.result())
   if len(records)%100==0 or len(records)==len(rows):
    compact=dict(stage='graph_cache',done=len(records),requested=len(rows),ok=sum(x['status']=='ok' for x in records),failed=sum(x['status']!='ok' for x in records),test_accessed=any(r['split']=='test' for r in rows),elapsed_seconds=round(time.time()-begin,2));atomic_json(work/'status.json',compact);print(json.dumps(compact),flush=True)
 report=dict(contract=c,requested=len(rows),covered=sum(x['status']=='ok' for x in records),coverage=sum(x['status']=='ok' for x in records)/len(rows) if rows else 0,records=sorted(records,key=lambda r:r['sample_id']),test_accessed=any(r['split']=='test' for r in rows),elapsed_seconds=round(time.time()-begin,2));atomic_json(work/report_name,report)
 if coverage_policy and coverage_policy['mode']=='audited_partial':
  save_eligibility(work,eligibility_name,rows,report_name,plan_fingerprint,c,coverage_policy)
 elif report['covered']!=report['requested']:raise RuntimeError('full graph coverage required; failures kept in '+str(work/report_name))
 return report


def progress(work,stage,done,total,**extra):
 d=dict(stage=stage,done=done,requested=total,updated_unix=time.time(),**extra);atomic_json(pathlib.Path(work)/'status.json',d);print(json.dumps(d),flush=True)

def import_cache(rows,c,work,source_report,package_paths,workers,p,plan_fingerprint):
 """Verify sources and successful graphs before copying to an isolated run. No PE execution."""
 check_runtime_contract(c);source_report=pathlib.Path(source_report).resolve();source_sha=file_sha(source_report);report=json.loads(source_report.read_text(encoding='utf8'))
 # Validate ALL identities, statuses and gates before any graph reuse.
 audit=build_manifest(rows,report,plan_fingerprint,c,p,'cache_report.json',source_sha)
 atomic_json(work/'reuse_source_audit.json',dict(source_report=str(source_report),source_report_sha256=source_sha,audit=audit))
 if not audit['gate_passed']:raise RuntimeError('source audit coverage gate failed')
 byid={r['sample_id']:r for r in rows};source_root=source_report.parent;records=[]
 def verify_copy(rec):
  r=byid[rec['sample_id']];sample=pathlib.Path(r['source_path']);before=sample.stat()
  if sample.is_symlink() or [before.st_size,before.st_mtime_ns]!=[r['size_bytes'],r['mtime_ns']]:raise ValueError('source stamp changed during cache reuse')
  if file_sha(sample)!=r['sample_id']:raise ValueError('source SHA256 mismatch during cache reuse')
  after=sample.stat()
  if [after.st_size,after.st_mtime_ns]!=[before.st_size,before.st_mtime_ns]:raise ValueError('source changed during cache reuse')
  out=dict(rec)
  if rec['status']=='ok':
   src=cache_file(source_root,c,r['sample_id']);dst=cache_file(work,c,r['sample_id'])
   if file_sha(src)!=rec['cache_sha256']:raise ValueError('reused graph cache digest mismatch')
   read_graph(src,r['sample_id'],c);dst.parent.mkdir(parents=True,exist_ok=True)
   if dst.exists():raise ValueError('import target already exists; use a new isolated work directory')
   shutil.copy2(src,dst)
   if file_sha(dst)!=rec['cache_sha256']:raise ValueError('copied graph cache digest mismatch')
   out['cache_path']=str(dst)
  return out
 with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
  pending={pool.submit(verify_copy,r):r for r in report['records']}
  for future in concurrent.futures.as_completed(pending):
   records.append(future.result())
   if len(records)%100==0 or len(records)==len(rows):progress(work,'verifying_cache_reuse',len(records),len(rows),test_accessed=False)
 if source_sha!=file_sha(source_report):raise ValueError('source cache report changed during reuse')
 updated=dict(report,records=sorted(records,key=lambda r:r['sample_id']),source_report=str(source_report),source_report_sha256=source_sha)
 atomic_json(work/'cache_report.json',updated)
 accepted,audit=save_eligibility(work,'train_val_eligibility.json',rows,'cache_report.json',plan_fingerprint,c,p)
 progress(work,'cache_reuse_frozen',len(accepted),len(rows),coverage=audit['coverage'],excluded=audit['excluded'],test_accessed=False)
 return audit

def verify_accepted_cache(rows,c,work,manifest):
 byid={e['sample_id']:e for e in manifest['entries']}
 for i,r in enumerate(rows):
  if i%100==0:progress(work,'verifying_frozen_cache',i,len(rows),test_accessed=any(r['split']=='test' for r in rows))
  sample=pathlib.Path(r['source_path']);s=sample.stat()
  if sample.is_symlink() or [s.st_size,s.st_mtime_ns]!=[r['size_bytes'],r['mtime_ns']]:raise ValueError('source stamp changed before training')
  if file_sha(cache_file(work,c,r['sample_id']))!=byid[r['sample_id']]['cache_sha256']:raise ValueError('frozen graph cache SHA256 changed')

def vocab_from_train(rows,c,work,max_vocab=1000):
 from models.MalGraph_2022.Vocabulary import Vocab
 counter=collections.Counter()
 for index,r in enumerate(rows):
  if index%100==0:progress(work,'vocabulary',index,len(rows),test_accessed=False)
  if r['split']!='train':raise ValueError('vocabulary may only see train role')
  g=read_graph(cache_file(work,c,r['sample_id']),r['sample_id'],c);counter.update(set(g['function_names'][len(g['acfg_list']):]))
 p=pathlib.Path(work)/'train_external_function_name_vocab.jsonl'
 with p.open('w',encoding='utf8') as f:
  for name,n in sorted(counter.items(),key=lambda kv:(-kv[1],kv[0])):f.write(json.dumps(dict(f_name=name,count=n),ensure_ascii=False)+'\n')
 return Vocab(str(p),max_vocab_size=max_vocab),p

def model_for(vocab,device):
 from models.MalGraph_2022.ParameterClasses import ModelParams
 from models.MalGraph_2022.malgraph import HierarchicalGraphNeuralNetwork
 return HierarchicalGraphNeuralNetwork(ModelParams(**PARAMS),vocab,logging.getLogger('retrain.malgraph')).to(device)

def graph_batch(rows,c,work,device):
 import torch
 from torch_geometric.data import Data,Batch
 local=[];positions=[0];external=[];fcg=[]
 for r in rows:
  g=read_graph(cache_file(work,c,r['sample_id']),r['sample_id'],c)
  for cfg in g['acfg_list']:local.append(Data(x=torch.tensor(cfg['block_features'],dtype=torch.float32),edge_index=torch.tensor(cfg['block_edges'],dtype=torch.long).reshape(2,-1)))
  positions.append(len(local));external.append(g['function_names'][len(g['acfg_list']):]);fcg.append(g['function_edges'])
 return Batch.from_data_list(local).to(device),positions,external,fcg,device

def score(model,rows,c,work,device,batch_size):
 import numpy as np,torch
 model.eval();ids=[];scores=[]
 with torch.no_grad():
  for i in range(0,len(rows),batch_size):
   if i%100==0:progress(work,'scoring',i,len(rows),role=rows[0]['split'],test_accessed=rows[0]['split']=='test')
   batch=rows[i:i+batch_size];p=model(*graph_batch(batch,c,work,device)).reshape(-1).cpu().numpy()
   if p.shape!=(len(batch),) or not np.isfinite(p).all() or np.any((p<0)|(p>1)):raise ValueError('nonfinite/misaligned graph probabilities')
   ids.extend(r['sample_id'] for r in batch);scores.extend(map(float,p))
 if ids!=[r['sample_id'] for r in rows]:raise ValueError('score IDs misaligned')
 return dict(sample_ids=ids,labels=[r['label_value'] for r in rows],scores=scores)

def torch_save(path,obj):
 import torch
 path=pathlib.Path(path);tmp=path.with_suffix(path.suffix+'.tmp');torch.save(obj,tmp);tmp.replace(path)

def guard_fit_workspace(work,resume):
 work=pathlib.Path(work);last=work/'last_checkpoint.pt';best=work/'best_checkpoint.pt'
 if resume and not last.exists():raise FileNotFoundError('--resume requires last_checkpoint.pt; no implicit fresh training')
 if not resume and (last.exists() or best.exists()):raise ValueError('existing checkpoint protected; use --resume or a new isolated work-dir')

def training_source_hashes():
 names=['train/retrain_malgraph_coverage.py','train/retrain_malgraph.py','train/retrain_selection.py','train/retrain_contract.py','engine/decision_policy.py','models/MalGraph_2022/malgraph.py','models/MalGraph_2022/ParameterClasses.py','models/MalGraph_2022/Vocabulary.py']
 return {n:file_sha(PROJECT/n) for n in names}

def fit(train,val,c,work,device,epochs,lr,patience,batch_size,seed,run_fingerprint,resume=False):
 import numpy as np,torch
 guard_fit_workspace(work,resume)
 if any(r['split']!='train' for r in train) or any(r['split']!='model_val' for r in val):raise ValueError('fit roles must be train/model_val')
 if {r['label_value'] for r in train}!={0,1} or {r['label_value'] for r in val}!={0,1}:raise ValueError('train and external validation require both labels')
 random.seed(seed);np.random.seed(seed);torch.manual_seed(seed)
 if torch.cuda.is_available():torch.cuda.manual_seed_all(seed)
 vocab,vocab_path=vocab_from_train(train,c,work);model=model_for(vocab,device);opt=torch.optim.Adam(model.parameters(),lr=lr);best=float('inf');stall=0;start=0;work=pathlib.Path(work);checkpoint=work/'last_checkpoint.pt';history=[]
 if resume and checkpoint.exists():
  d=torch.load(checkpoint,map_location=device,weights_only=True)
  if d['run_fingerprint']!=run_fingerprint or d['vocab_sha256']!=file_sha(vocab_path):raise ValueError('resume contract/vocabulary changed')
  model.load_state_dict(d['model_state'],strict=True);opt.load_state_dict(d['optimizer_state']);start=d['epoch']+1;best=d['best'];stall=d['stall'];history=d['history'];random.setstate(d['python_rng']);torch.set_rng_state(d['torch_rng'].cpu())
  if torch.cuda.is_available() and d.get('cuda_rng') is not None:torch.cuda.set_rng_state_all([x.cpu() for x in d['cuda_rng']])
  if stall>=patience:start=epochs  # A stopped run must not gain extra epochs on resume.
 for epoch in range(start,epochs):
  model.train();order=list(train);random.shuffle(order);used=[];total=0.
  for i in range(0,len(order),batch_size):
   if i%100==0:progress(work,'training',i,len(order),epoch=epoch+1,total_epochs=epochs,test_accessed=False)
   batch=order[i:i+batch_size];opt.zero_grad(set_to_none=True);p=model(*graph_batch(batch,c,work,device)).reshape(-1);y=torch.tensor([r['label_value'] for r in batch],dtype=torch.float32,device=device)
   loss=torch.nn.functional.binary_cross_entropy(p,y)
   if not torch.isfinite(loss):raise ValueError('nonfinite loss')
   loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),5.0,error_if_nonfinite=True);opt.step();total+=float(loss.detach())*len(batch);used.extend(r['sample_id'] for r in batch)
  if len(used)!=len(train) or set(used)!={r['sample_id'] for r in train}:raise ValueError('not all train rows used exactly once')
  vs=score(model,val,c,work,device,batch_size);vp=np.clip(vs['scores'],1e-7,1-1e-7);vy=np.array(vs['labels']);vl=float(np.mean(-vy*np.log(vp)-(1-vy)*np.log1p(-vp)))
  improved=vl<best
  if improved:best=vl;stall=0;torch_save(work/'best_checkpoint.pt',dict(schema='malgraph-trained-checkpoint-v1',run_fingerprint=run_fingerprint,model_state={k:v.detach().cpu() for k,v in model.state_dict().items()},model_params=PARAMS,vocab_sha256=file_sha(vocab_path),epoch=epoch))
  else:stall+=1
  item=dict(epoch=epoch+1,n_train=len(train),n_val=len(val),train_loss=total/len(train),val_loss=vl,all_train_rows_used=True);history.append(item);print(json.dumps(item),flush=True);atomic_json(work/'training_history.json',history)
  torch_save(checkpoint,dict(schema='malgraph-resume-checkpoint-v1',run_fingerprint=run_fingerprint,model_state=model.state_dict(),optimizer_state=opt.state_dict(),epoch=epoch,best=best,stall=stall,history=history,vocab_sha256=file_sha(vocab_path),python_rng=random.getstate(),torch_rng=torch.get_rng_state(),cuda_rng=torch.cuda.get_rng_state_all() if torch.cuda.is_available() else None))
  atomic_json(work/'status.json',dict(stage='training',epoch=epoch+1,n_train=len(train),n_val=len(val),test_accessed=False))
  if stall>=patience:break
 d=torch.load(work/'best_checkpoint.pt',map_location=device,weights_only=True)
 if d['run_fingerprint']!=run_fingerprint or d['vocab_sha256']!=file_sha(vocab_path):raise ValueError('best checkpoint identity mismatch')
 model.load_state_dict(d['model_state'],strict=True);return model,score(model,val,c,work,device,batch_size),history

def setup_paths(args):
 for p in reversed(args.package_path):sys.path.insert(0,str(pathlib.Path(p).resolve()))
 sys.path.insert(0,str(PROJECT));pathlib.Path(args.work_dir).mkdir(parents=True,exist_ok=True);os.environ['TORCHINDUCTOR_CACHE_DIR']=str(pathlib.Path(args.work_dir)/'torchinductor_cache')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('command',choices=['preflight','cache','import-cache','train','evaluate-test'])
 p.add_argument('--plan',type=pathlib.Path,required=True);p.add_argument('--work-dir',type=pathlib.Path,required=True)
 p.add_argument('--package-path',action='append',default=[]);p.add_argument('--workers',type=int,default=4)
 p.add_argument('--analysis-timeout',type=int,default=120);p.add_argument('--hard-timeout',type=int,default=180)
 p.add_argument('--device',choices=['cuda','cpu'],default='cuda');p.add_argument('--epochs',type=int,default=20)
 p.add_argument('--batch-size',type=int,default=4);p.add_argument('--lr',type=float,default=.001);p.add_argument('--patience',type=int,default=5)
 p.add_argument('--resume',action='store_true');p.add_argument('--coverage-policy',choices=['strict','audited_partial'],default='strict')
 p.add_argument('--source-cache-report',type=pathlib.Path);args=p.parse_args()
 if min(args.workers,args.epochs,args.batch_size,args.patience)<=0 or args.lr<=0:p.error('all hyperparameters must be positive')
 if args.command=='preflight' and args.coverage_policy!='strict':p.error('preflight requires strict coverage')
 setup_paths(args);plan=load_plan(args.plan);c=runtime_contract(args.analysis_timeout,args.hard_timeout);work=args.work_dir.resolve();cp=policy(args.coverage_policy);freeze_policy(work,cp)
 if (work/'graph_contract.json').exists() and json.loads((work/'graph_contract.json').read_text(encoding='utf8'))!=c:raise ValueError('existing graph contract changed')
 atomic_json(work/'graph_contract.json',c);roles={role:[r for r in plan['samples'] if r['split']==role] for role in ROLES};trainval=roles['train']+roles['model_val']
 if args.command in ('cache','import-cache') and ((work/'frozen_run.json').exists() or (work/'train_val_eligibility.json').exists()):raise ValueError('frozen run/cache audit protected; use isolated work-dir')
 if args.command=='import-cache':
  if not args.source_cache_report:raise ValueError('import-cache requires --source-cache-report')
  import_cache(trainval,c,work,args.source_cache_report,args.package_path,args.workers,cp,plan['plan_fingerprint']);return 0
 if args.command=='cache':
  ensure_cache(trainval,c,work,args.package_path,args.workers,coverage_policy=cp,plan_fingerprint=plan['plan_fingerprint'],eligibility_name='train_val_eligibility.json')
  if cp['mode']=='strict':save_eligibility(work,'train_val_eligibility.json',trainval,'cache_report.json',plan['plan_fingerprint'],c,cp)
  return 0
 def frozen_identity(frozen):
  if frozen['plan_fingerprint']!=plan['plan_fingerprint'] or frozen['graph_contract']!=c or frozen.get('coverage_policy')!=cp:raise ValueError('frozen plan/graph/coverage policy changed')
  if frozen['trainer_sha256']!=file_sha(__file__) or frozen['model_source_sha256']!=file_sha(PROJECT/'models/MalGraph_2022/malgraph.py') or frozen.get('training_sources')!=training_source_hashes():raise ValueError('frozen training/model source changed')
  if frozen.get('train_val_eligibility_sha256') and frozen['train_val_eligibility_sha256']!=file_sha(work/'train_val_eligibility.json'):raise ValueError('frozen train/val eligibility changed')
 if (work/'frozen_run.json').exists():frozen_identity(json.loads((work/'frozen_run.json').read_text(encoding='utf8')))
 def eligible(role):
  name=role+'_eligibility.json';report_name=role+'_cache_report.json'
  if (work/name).exists():
   accepted,audit=load_eligibility(work,name,roles[role],plan['plan_fingerprint'],c,cp);verify_accepted_cache(accepted,c,work,audit);return accepted,audit
  ensure_cache(roles[role],c,work,args.package_path,args.workers,report_name,cp,plan['plan_fingerprint'],name)
  return save_eligibility(work,name,roles[role],report_name,plan['plan_fingerprint'],c,cp)
 import torch
 if args.device=='cuda' and not torch.cuda.is_available():raise RuntimeError('requested CUDA unavailable; no implicit CPU fallback')
 device=torch.device(args.device)
 if args.command=='evaluate-test':
  candidate=json.loads((work/'candidate_manifest.json').read_text(encoding='utf8'));candidate_lock=json.loads((work/'candidate_lock.json').read_text(encoding='utf8'))
  if candidate_lock['candidate_sha256']!=file_sha(work/'candidate_manifest.json'):raise ValueError('frozen candidate manifest changed')
  frozen=json.loads((work/'frozen_run.json').read_text(encoding='utf8'));frozen_identity(frozen)
  if candidate['plan_fingerprint']!=plan['plan_fingerprint'] or candidate['graph_contract']!=c or candidate.get('coverage_policy')!=cp or candidate['frozen_run_sha256']!=file_sha(work/'frozen_run.json') or candidate['checkpoint_sha256']!=file_sha(work/'best_checkpoint.pt') or candidate['vocab_sha256']!=file_sha(work/'train_external_function_name_vocab.jsonl') or candidate['calibration_eligibility_sha256']!=file_sha(work/'calibration_eligibility.json') or candidate['calibration_scores_sha256']!=file_sha(work/'calibration_scores.json'):raise ValueError('test evaluation requires exact frozen candidate identity')
  # Verify calibration identity without rescoring it. Test is accessed only below this gate.
  cal_rows,_=load_eligibility(work,'calibration_eligibility.json',roles['calibration'],plan['plan_fingerprint'],c,cp)
  calibration_scores=json.loads((work/'calibration_scores.json').read_text(encoding='utf8'))
  from retrain_selection import select_threshold
  if calibration_scores['sample_ids']!=[r['sample_id'] for r in cal_rows] or calibration_scores['labels']!=[r['label_value'] for r in cal_rows] or candidate['decision']!=select_threshold('calibration',calibration_scores['labels'],calibration_scores['scores'],frozen['threshold_grid']):raise ValueError('frozen calibration decision/identity changed')
  test,test_audit=eligible('test')
  from models.MalGraph_2022.Vocabulary import Vocab
  vocab=Vocab(str(work/'train_external_function_name_vocab.jsonl'),max_vocab_size=1000);model=model_for(vocab,device);d=torch.load(work/'best_checkpoint.pt',map_location=device,weights_only=True)
  if d['run_fingerprint']!=frozen['run_fingerprint'] or d['vocab_sha256']!=candidate['vocab_sha256'] or d['model_params']!=PARAMS:raise ValueError('checkpoint contract mismatch')
  model.load_state_dict(d['model_state'],strict=True);scores=score(model,test,c,work,device,args.batch_size)
  atomic_json(work/'test_scores.json',dict(**scores,threshold=candidate['decision']['threshold'],threshold_fitted_on='calibration',test_used_for_selection=False,**population_metrics(test_audit)))
  from retrain_selection import threshold_metrics,auc
  atomic_json(work/'test_metrics.json',dict(**threshold_metrics(scores['labels'],scores['scores'],candidate['decision']['threshold']),auc=auc(scores['labels'],scores['scores']),comparator='strict_gt',test_used_for_selection=False,evaluation_scope=plan.get('purpose','held_out_test_of_frozen_research_candidate'),acceptance_certified=False,**population_metrics(test_audit)))
  atomic_json(work/'status.json',dict(stage='test_evaluated',n_test=len(test),test_accessed=True,test_used_for_selection=False,**population_metrics(test_audit),evaluation_scope=plan.get('purpose','held_out_test_of_frozen_research_candidate'),deployable=False,production_model_modified=False));return 0
 preflight=args.command=='preflight';eligibility_sha=None;train_audit=None
 if preflight:
  chosen={role:[] for role in ['train','model_val']}
  for role in chosen:
   for label in ['benign','malicious']:
    for typ in ['dll32','dll64','exe32','exe64']:
     eligible_rows=[r for r in roles[role] if r['label']==label and r['pe_type']==typ];chosen[role].append(min(eligible_rows,key=lambda r:digest([plan['seed'],r['sample_id']])))
  train,val=chosen['train'],chosen['model_val'];ensure_cache(train+val,c,work,args.package_path,args.workers,'preflight_cache_report.json')
 else:
  if cp['mode']=='audited_partial' or (work/'train_val_eligibility.json').exists():
   accepted,train_audit=load_eligibility(work,'train_val_eligibility.json',trainval,plan['plan_fingerprint'],c,cp)
   verify_accepted_cache(accepted,c,work,train_audit);train=[r for r in accepted if r['split']=='train'];val=[r for r in accepted if r['split']=='model_val'];eligibility_sha=file_sha(work/'train_val_eligibility.json')
  else:
   train,val=roles['train'],roles['model_val']
   for i,r in enumerate(train+val):
    if i%100==0:progress(work,'verifying_full_cache',i,len(train+val),test_accessed=False)
    read_graph(cache_file(work,c,r['sample_id']),r['sample_id'],c)
 frozen=dict(schema='malgraph-frozen-run-v2',plan_fingerprint=plan['plan_fingerprint'],graph_contract=c,coverage_policy=cp,train_val_eligibility_sha256=eligibility_sha,model_params=PARAMS,mode='from_scratch',max_vocab_size=1000,train_ids=[r['sample_id'] for r in train],val_ids=[r['sample_id'] for r in val],seed=plan['seed'],epochs=1 if preflight else args.epochs,lr=args.lr,patience=args.patience,batch_size=args.batch_size,device=args.device,threshold_grid=[round(.05*i,2) for i in range(1,20)],preflight_only=preflight,trainer_sha256=file_sha(__file__),model_source_sha256=file_sha(PROJECT/'models/MalGraph_2022/malgraph.py'),torch_version=torch.__version__,training_sources=training_source_hashes())
 frozen['run_fingerprint']=digest(frozen)
 if (work/'frozen_run.json').exists() and json.loads((work/'frozen_run.json').read_text(encoding='utf8'))!=frozen:raise ValueError('existing work directory contains a different run; use isolated work-dir')
 atomic_json(work/'frozen_run.json',frozen);model,vs,history=fit(train,val,c,work,device,frozen['epochs'],args.lr,args.patience,args.batch_size,plan['seed'],frozen['run_fingerprint'],args.resume);atomic_json(work/'model_val_scores.json',vs)
 if preflight:
  doc=dict(status='real_pe_cuda_preflight_passed' if args.device=='cuda' else 'real_pe_cpu_preflight_passed',n_train=len(train),n_val=len(val),preflight_only=True,selection_method='seeded_hash_first_per_role_label_type',full_training_complete=False,test_accessed=False,weights_reloaded_strictly=True,graph_contract=c,history=history,deployable=False);atomic_json(work/'preflight_result.json',doc);print(json.dumps(doc),flush=True);return 0
 # Weights/vocabulary AND four-role coverage policy are locked before first calibration access.
 atomic_json(work/'weights_locked.json',dict(run_fingerprint=frozen['run_fingerprint'],checkpoint_sha256=file_sha(work/'best_checkpoint.pt'),vocab_sha256=file_sha(work/'train_external_function_name_vocab.jsonl'),coverage_policy=cp))
 calibration,cal_audit=eligible('calibration');cs=score(model,calibration,c,work,device,args.batch_size);atomic_json(work/'calibration_scores.json',dict(**cs,**population_metrics(cal_audit)))
 from retrain_selection import select_threshold
 decision=select_threshold('calibration',cs['labels'],cs['scores'],frozen['threshold_grid'])
 doc=dict(schema='malgraph-research-candidate-v2',status='complete_research_candidate',purpose=plan.get('purpose','research_candidate_not_deployment_acceptance'),plan_fingerprint=plan['plan_fingerprint'],graph_contract=c,coverage_policy=cp,model_params=PARAMS,decision=decision,checkpoint_path=str(work/'best_checkpoint.pt'),checkpoint_sha256=file_sha(work/'best_checkpoint.pt'),vocab_sha256=file_sha(work/'train_external_function_name_vocab.jsonl'),frozen_run_sha256=file_sha(work/'frozen_run.json'),train_val_eligibility_sha256=eligibility_sha,calibration_eligibility_sha256=file_sha(work/'calibration_eligibility.json'),calibration_scores_sha256=file_sha(work/'calibration_scores.json'),n_train=len(train),n_val=len(val),n_calibration=len(calibration),original_n_train=len(roles['train']),original_n_val=len(roles['model_val']),original_n_calibration=len(roles['calibration']),all_eligible_train_rows_used=True,all_original_train_rows_used=len(train)==len(roles['train']),calibration_population=population_metrics(cal_audit),test_accessed=False,deployable=False,production_model_modified=False)
 if (work/'candidate_manifest.json').exists() and json.loads((work/'candidate_manifest.json').read_text(encoding='utf8'))!=doc:raise ValueError('existing candidate protected; resume must preserve exact identity')
 atomic_json(work/'candidate_manifest.json',doc);atomic_json(work/'candidate_lock.json',dict(candidate_sha256=file_sha(work/'candidate_manifest.json'),test_used_for_selection=False));atomic_json(work/'status.json',doc);print(json.dumps(doc),flush=True);return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:print(type(e).__name__+': '+str(e),file=sys.stderr,flush=True);raise
