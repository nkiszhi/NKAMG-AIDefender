import asyncio,json,unittest
from fastapi import Response
import main

class ApiCollectionProjection(unittest.TestCase):
 def row(self):
  return {'task_id':'a'*32,'status':'completed','result_json':json.dumps({'sha256':'b'*64,'file_path':'private',
    'exe_result':{'MalConv':{'result':'Malicious','probability':.9},'集成结果':{'result':'Malicious','display_result':'Generic.ML.High','source':'models'},'unknown':{'secret':'hidden'}}})}
 def test_default_protocol_is_unchanged(self):
  self.assertEqual(asyncio.run(main._api_final_result(self.row(),Response(),0)),{'result':'Generic.ML.High'})
 def test_opt_in_returns_only_existing_approved_results_without_private_metadata(self):
  out=asyncio.run(main._api_final_result(self.row(),Response(),0,include_details=True))
  self.assertEqual(set(out),{'result','sha256','model_results','codefender_result'})
  self.assertEqual(set(out['model_results']),{'MalConv'});self.assertEqual(out['sha256'],'b'*64)
 def test_invalid_final_is_not_promoted_to_success_by_details(self):
  row=self.row();r=json.loads(row['result_json']);r['exe_result']['集成结果']={'result':'Failed'};row['result_json']=json.dumps(r)
  out=asyncio.run(main._api_final_result(row,Response(),0,include_details=True));self.assertEqual(out.status_code,502)

if __name__=='__main__':unittest.main()
