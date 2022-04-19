import json
import os
import shutil
from glob import glob
from tqdm import tqdm
import uefi_firmware
import click
from concurrent.futures import ProcessPoolExecutor, as_completed
from guid_db import UEFI_GUIDS
from utils import get_machine_type, IMAGE_FILE_MACHINE_I386

CONFIG_PATH = 'config.json'
with open(CONFIG_PATH, 'rb') as config_file:
    CONFIG = json.load(config_file)
LOG_PATH = "./helper/logs"
IDA_PATH = '"{}"'.format(CONFIG['IDA_PATH'])
IDA64_PATH = '"{}"'.format(CONFIG['IDA64_PATH'])


def clear(dirname):
    for root, dirs, files in os.walk(dirname, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(dirname)


def init_dirs():
    if not os.path.exists(CONFIG['PE_DIR']):
        os.mkdir(CONFIG['PE_DIR'])
    if not os.path.exists(LOG_PATH):
        os.mkdir(LOG_PATH)


def clear_ida_bak(dirname):
    re = os.path.join(os.path.dirname(__file__), dirname, "*.*")
    for file in glob(re):
        os.remove(file)


# get uefi pe files in uefi bin
def get_pe_files(bin_path, output_path):
    with open(bin_path, 'rb') as fw:
        file_content = fw.read()
    # parse uefi bin with uefi_firmware
    parser = uefi_firmware.AutoParser(file_content)
    if parser.type() == 'unknown':
        print('[-] This type of binary is not supported')
    firmware = parser.parse()
    temp_dir = "./output_temp"
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    firmware.dump(temp_dir)
    find_pe_files(temp_dir, output_path)
    clear(temp_dir)


def find_pe_files(dump_path, output_path):
    for root, dirs, files in os.walk(dump_path):
        if "file-" in root:
            pe_paths = os.path.join(root, "*.pe")
            if len(glob(pe_paths)) != 0:
                pe_path = glob(pe_paths)[0]
                # parse ui section
                ui_paths = os.path.join(root, "*ui")
                if len(glob(ui_paths)) != 0:
                    with open(glob(ui_paths)[0], 'rb') as ui:
                        pe_name = ui.read().replace(b'\x00', b'').decode('utf-8')
                else:
                    pe_guid = root.split("file-")[-1].split("/")[0].upper()
                    pe_name = UEFI_GUIDS.get(pe_guid)
                    if not pe_name:
                        pe_name = pe_guid
                dst = os.path.join(output_path, pe_name)
                # copy pe file to dest
                shutil.copy(pe_path, dst)
            else:
                continue


def analyse_module(module):
    module_path = os.path.join(os.path.dirname(__file__), CONFIG['PE_DIR'], module)
    machine_type = get_machine_type(module_path)
    ida_path = IDA64_PATH
    if machine_type == IMAGE_FILE_MACHINE_I386:
        ida_path = IDA_PATH
    analyser = os.path.join(os.path.dirname(__file__), 'helper', "analyse.py")
    cmd = ' '.join([ida_path, '-c -A -S{}'.format(analyser), module_path])
    os.system(cmd)


def generate_result():
    re = os.path.join(os.path.dirname(__file__), "helper/logs", "*.txt")
    logs = []
    for file in glob(re):
        with open(file, 'r') as f:
            logs.append({"filename": file.split("/")[-1].strip(".txt"), "value": json.loads(f.read())})
    result_path = os.path.join(os.path.dirname(__file__), "result.txt")
    with open(result_path, 'wb') as f:
        f.write(json.dumps(logs).encode())


@click.command()
@click.option("-w", '--max_workers', default=6, help="Number of workers", type=int)
@click.option("-b", "--binary", help="path of UEFI bin")
def start_analyse(max_workers, binary):
    init_dirs()
    get_pe_files(binary, CONFIG['PE_DIR'])
    temp = os.listdir(CONFIG['PE_DIR'])
    modules = []
    for module in temp:
        # analyse UEFI Driver only skip pei file
        if "pei" in module.lower():
            continue
        modules.append(module)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(analyse_module, module)
            for module in modules
        ]
        # process bar
        params = {
            'total': len(futures),
            'unit': 'module',
            'unit_scale': True,
            'leave': True
        }
        for _ in tqdm(as_completed(futures), **params):
            pass
    generate_result()
    clear_ida_bak("modules")


if __name__ == '__main__':
    start_analyse()
