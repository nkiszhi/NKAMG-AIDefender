"""Start the audited partial-coverage MalGraph stage; never claim 33-model completion.
Each stage must succeed before the next. Only frozen, audited applicability exclusions; no deployment.
"""
import argparse,collections,datetime,json,os,pathlib,shutil,subprocess,sys,traceback
from retrain_malgraph_contract import atomic_json,file_sha,load_plan,runtime_contract
from retrain_malgraph_coverage import policy,freeze_policy
PROJECT=pathlib.Path(__file__).resolve().parents[1]

def now():
 return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat()

def validate_full_plan(plan,quota=3728):
 counts=collections.Counter((r['label'],r['pe_type']) for r in plan['samples'])
 expected={(label,typ):quota for label in ['benign','malicious'] for typ in ['dll32','dll64','exe32','exe64']}
 if dict(counts)!=expected:raise ValueError('exact eight-stratum full quota required; no implicit exclusion')
 return {'selected':len(plan['samples']),'quota_per_stratum':quota,'strata':{label+'/'+typ:n for (label,typ),n in counts.items()},'roles':plan['counts']}

def protected_baseline(path,expected):
 actual=file_sha(path)
 if actual!=expected:raise ValueError('production baseline changed; stop without deployment')
 return actual

def build_stage_commands(args):
 entry=PROJECT/'train'/'retrain_malgraph.py';work=args.job_dir/'malgraph'
 common=['--coverage-policy','audited_partial','--plan',str(args.plan),'--work-dir',str(work),'--package-path',str(args.package_path),'--device',args.device,'--workers',str(args.workers),'--analysis-timeout',str(args.analysis_timeout),'--hard-timeout',str(args.hard_timeout),'--batch-size',str(args.batch_size)]
 commands=[]
 for stage in ['import-cache','train','evaluate-test']:
  command=[sys.executable,'-X','utf8',str(entry),stage]+common
  if stage=='import-cache':command+=['--source-cache-report',str(args.source_cache_report)]
  if stage=='train':
   command+=['--epochs',str(args.epochs),'--lr',str(args.lr),'--patience',str(args.patience)]
  commands.append((stage,command))
 return commands

def run_stages(commands,execute,on_stage):
 for stage,command in commands:
  on_stage(stage)
  code=execute(stage,command)
  if code:return {'status':'failed_closed','failed_stage':stage,'returncode':code,'later_stages_not_started':True}
 return {'status':'malgraph_stage_complete_other_models_not_started','returncode':0,'later_stages_not_started':False}

def parser():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--plan',required=True,type=pathlib.Path);p.add_argument('--readiness',required=True,type=pathlib.Path)
 p.add_argument('--job-dir',required=True,type=pathlib.Path);p.add_argument('--package-path',required=True,type=pathlib.Path)
 p.add_argument('--device',choices=['cuda','cpu'],default='cuda');p.add_argument('--workers',type=int,default=4)
 p.add_argument('--analysis-timeout',type=int,default=60);p.add_argument('--hard-timeout',type=int,default=100)
 p.add_argument('--epochs',type=int,default=20);p.add_argument('--batch-size',type=int,default=1)
 p.add_argument('--lr',type=float,default=.001);p.add_argument('--patience',type=int,default=5)
 p.add_argument('--source-cache-report',required=True,type=pathlib.Path)
 return p

def main(argv=None):
 a=parser().parse_args(argv)
 for k in ['plan','readiness','job_dir','package_path','source_cache_report']:setattr(a,k,getattr(a,k).resolve())
 workspace=PROJECT.parent
 if not a.job_dir.is_relative_to(workspace/'outputs') or a.job_dir==workspace/'outputs':raise ValueError('job must be inside workspace outputs')
 if min(a.workers,a.epochs,a.batch_size,a.patience)<=0 or not a.lr>0:raise ValueError('positive hyperparameters required')
 a.job_dir.mkdir(parents=True,exist_ok=True)
 if (a.job_dir/'request.json').exists() or (a.job_dir/'status.json').exists():raise ValueError('existing job protected; use a new job directory')
 sys.path.insert(0,str(a.package_path));sys.path.insert(0,str(PROJECT))
 plan=load_plan(a.plan);inventory=validate_full_plan(plan);ready=json.loads(a.readiness.read_text(encoding='utf8'))
 baseline=pathlib.Path(ready['baseline']).resolve();baseline_sha=protected_baseline(baseline,ready['baseline_sha256'])
 if baseline!=PROJECT/'ensemble.pkl':raise ValueError('unexpected protected baseline path')
 contract=runtime_contract(a.analysis_timeout,a.hard_timeout);commands=build_stage_commands(a);cp=policy('audited_partial');freeze_policy(a.job_dir/'malgraph',cp)
 request={'schema':'full-retrain-launch-v1','created_at':now(),'launcher_pid':os.getpid(),'scope':'audited_partial_MalGraph_stage_not_33_model_joint_training','plan':str(a.plan),'plan_sha256':file_sha(a.plan),'plan_fingerprint':plan['plan_fingerprint'],'inventory':inventory,'baseline':str(baseline),'baseline_sha256':baseline_sha,'python':sys.executable,'device':a.device,'graph_contract':contract,'commands':dict(commands),'launcher_sha256':file_sha(__file__),'trainer_sha256':file_sha(PROJECT/'train'/'retrain_malgraph.py'),'sample_exclusion_authorized':True,'coverage_policy':cp,'source_cache_report':str(a.source_cache_report),'source_cache_report_sha256':file_sha(a.source_cache_report),'coverage_source_sha256':file_sha(PROJECT/'train'/'retrain_malgraph_coverage.py'),'silent_filtering':False,'deployable':False,'production_model_modified':False,'other_models':[{'model':r['model'],'status':'not_started','reason':'full_feature_coverage_and_joint_coordinator_not_yet_ready'} for r in ready['models'] if r['model']!='MalGraph']}
 atomic_json(a.job_dir/'request.json',request)
 state={'schema':'full-retrain-launch-status-v1','started_at':now(),'launcher_pid':os.getpid(),'status':'preparing','scope':request['scope'],'selected_records':inventory['selected'],'stage':'preparing','model_training_started':False,'all_33_models_started':False,'full_training_complete':False,'deployable':False,'production_model_modified':False,'other_model_count_not_started':len(request['other_models'])}
 def save():
  state['updated_at']=now();atomic_json(a.job_dir/'status.json',state)
 save()
 try:
  def on_stage(stage):
   state.update(status='running',stage=stage,stage_started_at=now(),training_process_launched=stage in ['train','evaluate-test']);save()
  def execute(stage,command):
   protected_baseline(baseline,baseline_sha)
   if file_sha(a.source_cache_report)!=request['source_cache_report_sha256'] or file_sha(PROJECT/'train'/'retrain_malgraph_coverage.py')!=request['coverage_source_sha256'] or file_sha(a.plan)!=request['plan_sha256'] or file_sha(__file__)!=request['launcher_sha256'] or file_sha(PROJECT/'train'/'retrain_malgraph.py')!=request['trainer_sha256']:raise ValueError('frozen launch identity changed')
   stdout=a.job_dir/(stage+'.stdout.log');stderr=a.job_dir/(stage+'.stderr.log')
   with stdout.open('ab',buffering=0) as out,stderr.open('ab',buffering=0) as err:
    child=subprocess.Popen(command,cwd=PROJECT,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    state['stage_pid']=child.pid;state['stdout_log']=str(stdout);state['stderr_log']=str(stderr);save()
    while True:
     try:code=child.wait(timeout=30);break
     except subprocess.TimeoutExpired:
      progress_path=a.job_dir/'malgraph'/'status.json'
      if progress_path.exists():
       detail=json.loads(progress_path.read_text(encoding='utf8'));state['model_progress']=detail
       if detail.get('stage')=='training':state['model_training_started']=True
       if detail.get('test_accessed'):state['test_accessed']=True
       save()
   protected_baseline(baseline,baseline_sha);state.setdefault('stage_results',{})[stage]={'returncode':code,'finished_at':now()};save();return code
  result=run_stages(commands,execute,on_stage);state.update(result);state['finished_at']=now()
  report=a.job_dir/'malgraph'/'cache_report.json'
  if report.exists():
   r=json.loads(report.read_text(encoding='utf8'));state['train_val_graph_coverage']={k:r[k] for k in ['requested','covered','coverage']};state['graph_failure_count']=r['requested']-r['covered']
  state['malgraph_training_complete']=result['returncode']==0;state['full_training_complete']=False;state['baseline_verified_unchanged']=protected_baseline(baseline,baseline_sha);save()
  return result['returncode']
 except BaseException as error:
  state.update(status='failed_closed',error=type(error).__name__+': '+str(error),finished_at=now(),full_training_complete=False)
  try:state['baseline_verified_unchanged']=protected_baseline(baseline,baseline_sha)
  except Exception as guard_error:state['baseline_guard_error']=str(guard_error)
  save();raise

if __name__=='__main__':
 try:sys.exit(main())
 except Exception:traceback.print_exc();sys.exit(1)
