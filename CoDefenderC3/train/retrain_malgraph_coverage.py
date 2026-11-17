"""Audited MalGraph applicability gates, independent of the frozen graph extractor."""
import collections,json,pathlib,re
from retrain_malgraph_contract import atomic_json,digest,file_sha,ROLES

KNOWN_ERRORS={
 'ValueError: SMDA completed without resolvable functions; no dummy graph allowed':'no_resolvable_functions',
 'ValueError: SMDA native status is error':'native_error',
 'ValueError: SMDA native status is timeout':'native_timeout',
 'ValueError: graph resource limit exceeded':'graph_resource_limit',
}

def policy(mode='strict'):
 if mode not in ('strict','audited_partial'):raise ValueError('unknown coverage policy')
 d=dict(schema='malgraph-coverage-policy-v1',mode=mode,minimum_overall_basis_points=10000 if mode=='strict' else 9500,minimum_stratum_basis_points=10000 if mode=='strict' else 9000,stratum_keys=['split','label','pe_type'],overall_scope='train_and_model_val_combined; calibration_and_test_separately',allowed_sample_failures=sorted(set(KNOWN_ERRORS.values())|{'unsupported_architecture','hard_timeout'}),unknown_errors_fatal=True,all_four_role_policy_frozen_before_training=True,excluded_samples_are_abstentions=True)
 d['fingerprint']=digest(d);return d

def freeze_policy(work,p):
 target=pathlib.Path(work)/'coverage_policy.json'
 if target.exists() and json.loads(target.read_text(encoding='utf8'))!=p:raise ValueError('coverage policy changed; isolated run required')
 atomic_json(target,p)

def reason(record):
 error=record.get('error','');status=record.get('status')
 if status=='timeout' and error=='native worker hard-killed at timeout':return 'hard_timeout'
 if status=='error' and error in KNOWN_ERRORS:return KNOWN_ERRORS[error]
 if status=='error' and re.fullmatch(r'ValueError: PE architecture unsupported by pinned intel backend: 0x[0-9a-f]{4}',error):return 'unsupported_architecture'
 return None

def build_manifest(rows,report,plan_fingerprint,c,p,report_name,report_sha):
 if p!=policy(p.get('mode')):raise ValueError('coverage policy fingerprint/semantics changed')
 if report.get('contract')!=c:raise ValueError('coverage report graph contract changed')
 originals={r['sample_id']:r for r in rows};records=report.get('records',[]);indexed={r['sample_id']:r for r in records}
 if not rows or len(originals)!=len(rows) or len(indexed)!=len(records) or set(indexed)!=set(originals):raise ValueError('coverage report missing/duplicate/unknown sample IDs')
 roles=sorted({r['split'] for r in rows})
 if set(roles) not in ({'train','model_val'},{'calibration'},{'test'}):raise ValueError('invalid eligibility role population')
 counts=collections.Counter();accepted=collections.Counter();entries=[];fatal=[]
 for sid in sorted(originals):
  r=originals[sid];rec=indexed[sid]
  if r['label'] not in ('benign','malicious') or type(r['label_value']) is not int or r['label_value']!=int(r['label']=='malicious') or r['pe_type'] not in ('dll32','dll64','exe32','exe64'):raise ValueError('eligibility label/type alignment invalid')
  if rec.get('split')!=r['split'] or rec.get('contract_fingerprint',c['fingerprint'])!=c['fingerprint']:raise ValueError('coverage record role/contract mismatch')
  key=(r['split'],r['label'],r['pe_type']);counts[key]+=1;ok=rec.get('status')=='ok';why=None
  if ok:
   if rec.get('error') or not re.fullmatch('[a-f0-9]{64}',rec.get('cache_sha256','')):raise ValueError('successful record has invalid cache digest/error')
   accepted[key]+=1
  else:
   why=reason(rec)
   if why is None:fatal.append(dict(sample_id=sid,error=rec.get('error'),status=rec.get('status')))
  entries.append(dict(sample_id=sid,split=r['split'],label=r['label'],label_value=r['label_value'],pe_type=r['pe_type'],source_path=r['source_path'],size_bytes=r['size_bytes'],mtime_ns=r['mtime_ns'],accepted=ok,reason=why if not ok else None,error=rec.get('error') if not ok else None,cache_sha256=rec.get('cache_sha256') if ok else None))
 n_ok=sum(accepted.values());total=len(rows)
 if report.get('requested')!=total or report.get('covered')!=n_ok or abs(report.get('coverage',-1)-n_ok/total)>1e-12:raise ValueError('coverage report counters inconsistent')
 strata=[dict(split=k[0],label=k[1],pe_type=k[2],requested=n,scorable=accepted[k],excluded=n-accepted[k],coverage=accepted[k]/n,passed=accepted[k]*10000>=n*p['minimum_stratum_basis_points']) for k,n in sorted(counts.items())]
 both=all({r['label_value'] for r in rows if r['split']==role and indexed[r['sample_id']]['status']=='ok'}=={0,1} for role in roles)
 passed=not fatal and both and n_ok*10000>=total*p['minimum_overall_basis_points'] and all(s['passed'] for s in strata)
 d=dict(schema='malgraph-eligibility-v1',plan_fingerprint=plan_fingerprint,graph_contract=c,policy=p,roles=roles,report_name=report_name,report_sha256=report_sha,population=total,scorable=n_ok,excluded=total-n_ok,coverage=n_ok/total,strata=strata,both_labels_in_each_role=both,fatal_errors=fatal,gate_passed=passed,entries=entries,metrics_scope='scorable_subset_conditional; exclusions_are_abstentions_not_correct_predictions',test_accessed='test' in roles)
 d['fingerprint']=digest(d);return d

def save_eligibility(work,name,rows,report_name,plan_fingerprint,c,p):
 work=pathlib.Path(work);report_path=work/report_name;report=json.loads(report_path.read_text(encoding='utf8'))
 d=build_manifest(rows,report,plan_fingerprint,c,p,report_name,file_sha(report_path));target=work/name
 if target.exists() and json.loads(target.read_text(encoding='utf8'))!=d:raise ValueError('frozen eligibility changed')
 atomic_json(target,d)
 if not d['gate_passed']:raise RuntimeError('audited coverage gate failed; see '+str(target))
 ids={e['sample_id'] for e in d['entries'] if e['accepted']};return [r for r in rows if r['sample_id'] in ids],d

def load_eligibility(work,name,rows,plan_fingerprint,c,p):
 work=pathlib.Path(work);d=json.loads((work/name).read_text(encoding='utf8'))
 if pathlib.Path(d['report_name']).name!=d['report_name']:raise ValueError('eligibility report must be a local filename')
 report_path=work/d['report_name'];report=json.loads(report_path.read_text(encoding='utf8'))
 expected=build_manifest(rows,report,plan_fingerprint,c,p,d['report_name'],file_sha(report_path))
 if d!=expected or not d['gate_passed']:raise ValueError('frozen eligibility/report identity or gate changed')
 ids={e['sample_id'] for e in d['entries'] if e['accepted']};return [r for r in rows if r['sample_id'] in ids],d

def population_metrics(d):
 return dict(population=d['population'],scorable=d['scorable'],abstentions=d['excluded'],coverage=d['coverage'],strata=d['strata'],eligibility_fingerprint=d['fingerprint'],metrics_scope=d['metrics_scope'])
