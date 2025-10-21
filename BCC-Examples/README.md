## BCC examples ported to PythonBPF

This repository contains examples of BCC tutorial examples that have been ported to use **PythonBPF**.

## Requirements
- install `pythonbpf` and `pylibbpf` using pip.
- You will also need `matplotlib` for vfsreadlat.py example.
- You will also need `rich` for vfsreadlat_rich.py example.
- You will also need `plotly` and `dash` for vfsreadlat_plotly.py example.

## Usage
- You'll need root privileges to run these examples. If you are using a virtualenv, use the following command to run the scripts:
  ```bash
  sudo <path_to_virtualenv>/bin/python3 <script_name>.py
  ```
- For vfsreadlat_plotly.py, run the following command to start the Dash server:
  ```bash
  sudo <path_to_virtualenv>/bin/python3 vfsreadlat_plotly/bpf_program.py
  ```
  Then open your web browser and navigate to the given URL.
