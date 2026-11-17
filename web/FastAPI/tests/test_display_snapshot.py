import json,unittest
from types import SimpleNamespace
from unittest.mock import MagicMock
from app.stats_repository import StatsRepository

class DisplaySnapshot(unittest.TestCase):
 def setUp(self):
  self.repo=StatsRepository(SimpleNamespace(domain_stats_mode='snapshot'))
  self.data={'total':123,'monthly':[{'name':'2026-11','count':12}],'source':[{'name':'a','count':100}],'category':[],'updated_at':'2026-11-17T04:38:25+08:00'}
 def test_only_single_snapshot_row_is_read(self):
  cur=MagicMock();cur.fetchone.return_value={'schema_version':1,'payload':json.dumps(self.data)}
  self.assertEqual(self.repo._domain_stats(cur),self.data)
  cur.execute.assert_called_once_with("SELECT schema_version,payload FROM web_display_snapshot WHERE snapshot_key='url_dashboard'")
 def test_null_and_wrong_version_are_not_fabricated_zeroes(self):
  for row in (None,{'schema_version':2,'payload':{}}):
   cur=MagicMock();cur.fetchone.return_value=row
   with self.assertRaises(RuntimeError):self.repo._domain_stats(cur)
 def test_corrupt_counts_rejected(self):
  for value in (True,-1,'100'):
   cur=MagicMock();cur.fetchone.return_value={'schema_version':1,'payload':{**self.data,'total':value}}
   with self.assertRaises(RuntimeError):self.repo._domain_stats(cur)
 def test_bad_ranked_rows_rejected(self):
  cur=MagicMock();cur.fetchone.return_value={'schema_version':1,'payload':{**self.data,'source':[{'name':'x','count':-5}]}}
  with self.assertRaises(RuntimeError):self.repo._domain_stats(cur)

if __name__=='__main__':unittest.main()
