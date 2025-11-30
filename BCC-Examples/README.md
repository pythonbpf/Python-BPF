## BCC examples ported to PythonBPF

This folder contains examples of BCC tutorial examples that have been ported to use **PythonBPF**.

## Requirements
- install `pythonbpf` and `pylibbpf` using pip.
- You will also need `matplotlib` for vfsreadlat.py example.
- You will also need `rich` for vfsreadlat_rich.py example.
- You will also need `plotly` and `dash` for vfsreadlat_plotly.py example.
- All of these are added to `requirements.txt` file. You can install them using the following command:
  ```bash
  pip install -r requirements.txt
  ```

## Usage
- You'll need root privileges to run these examples. If you are using a virtualenv, use the following command to run the scripts:
  ```bash
  sudo <path_to_virtualenv>/bin/python3 <script_name>.py
  ```
- For the disksnoop and container-monitor examples, you need to generate the vmlinux.py file first. Follow the instructions in the [main README](https://github.com/pythonbpf/Python-BPF/tree/master?tab=readme-ov-file#first-generate-the-vmlinuxpy-file-for-your-kernel) to generate the vmlinux.py file.
- For vfsreadlat_plotly.py, run the following command to start the Dash server:
  ```bash
  sudo <path_to_virtualenv>/bin/python3 vfsreadlat_plotly/bpf_program.py
  ```
  Then open your web browser and navigate to the given URL.
- For container-monitor, you need to first copy the vmlinux.py to `container-monitor/` directory.
  Then run the following command to run the example:
  ```bash
    sudo <path_to_virtualenv>/bin/python3 container-monitor/container_monitor.py
  ```
