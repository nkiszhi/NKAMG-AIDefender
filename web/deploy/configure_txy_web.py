"""Opt-in txy Web configuration. Does not invoke or reconfigure Docker."""
import argparse
import configparser
from datetime import datetime
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--revision',required=True,help='Actual model/weight/options/resource-budget version')
    args = parser.parse_args()
    web = args.repo.resolve()/'web'
    path = web/'config.ini'
    if not path.is_file():
        parser.error('Existing private web/config.ini is required; never replace it with the example')
    config = configparser.ConfigParser(interpolation=None)
    config.read(path,encoding='utf-8-sig')
    snapshot = Path('/run/codefender-resource-monitor/model-runtime.json')
    changes = {
        'server': {'max_concurrent_scans':'2','large_sample_bytes':'104857600','max_queue_wait_seconds':'1800'},
        'uploads': {'api_upload_timeout_seconds':'600'},
        'codefender': {'api_bases':'http://127.0.0.1:18011,http://127.0.0.1:18012',
            'scan_endpoint':'','predict_endpoint':'/predict-single','response_contract':'development',
            'include_de':'true','timeout':'1020','resource_monitor_path':str(snapshot),
            'resource_monitor_stale_seconds':'15','min_available_memory_bytes':'4294967296',
            'recovery_timeout_seconds':'1200','model_revision':args.revision}}
    backup = web/'FastAPI/data/config-backups'/('config-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.ini')
    backup.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(path,backup)
    for section,values in changes.items():
        if not config.has_section(section):
            config.add_section(section)
        for key,value in values.items():
            config.set(section,key,value)
    temp = path.with_name(path.name+'.resilience.tmp')
    with temp.open('w',encoding='utf-8',newline='\n') as handle:
        config.write(handle)
    shutil.copymode(path,temp)
    temp.replace(path)
    print('Updated Web configuration:',path)
    print('Private configuration backup:',backup)
    print('Monitor snapshot:',snapshot)
    print('Docker limits were NOT changed. Start the monitor before Web.')


if __name__=='__main__':
    main()
