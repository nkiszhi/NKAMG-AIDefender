import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('stop_web_for_update', Path(__file__).resolve().parents[2]/'deploy/stop_web_for_update.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class StopWebTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path('test-repo').resolve()
        self.processes = {
            100:{'cwd':self.repo/'web/Vue','args':['node','node_modules/.bin/vite','preview'],'start':'first'},
            200:{'cwd':self.repo/'web/FastAPI','args':['python','-u','main.py'],'start':'second'}}

    def test_busy_model_stops_nothing(self):
        with patch.object(deploy,'model_health',return_value={'active_tasks':1}), patch.object(deploy.os,'kill') as kill:
            with self.assertRaises(RuntimeError): deploy.stop(self.repo,True)
        kill.assert_not_called()

    def test_wrong_second_process_prevents_stopping_first(self):
        self.processes[200]['cwd']=self.repo/'another-project'
        with patch.object(deploy,'model_health',return_value={'active_tasks':0}), \
             patch.object(deploy,'listener_pids',side_effect=[{100},{200}]), \
             patch.object(deploy,'process_info',side_effect=self.processes.get), patch.object(deploy.os,'kill') as kill:
            with self.assertRaises(RuntimeError): deploy.stop(self.repo,True)
        kill.assert_not_called()

    def test_check_only_does_not_signal(self):
        with patch.object(deploy,'model_health',return_value={'active_tasks':0}), \
             patch.object(deploy,'listener_pids',side_effect=[{100},{200}]), \
             patch.object(deploy,'process_info',side_effect=self.processes.get), patch.object(deploy.os,'kill') as kill:
            deploy.stop(self.repo)
        kill.assert_not_called()

    def test_apply_signals_only_verified_processes_and_waits_for_exit(self):
        def signal_process(pid, sig): self.processes.pop(pid)
        with patch.object(deploy,'model_health',return_value={'active_tasks':0}), \
             patch.object(deploy,'listener_pids',side_effect=[{100},{200},set(),set()]), \
             patch.object(deploy,'process_info',side_effect=self.processes.get), \
             patch.object(deploy.os,'kill',side_effect=signal_process) as kill:
            deploy.stop(self.repo,True)
        self.assertEqual([call.args[0] for call in kill.call_args_list],[100,200])
