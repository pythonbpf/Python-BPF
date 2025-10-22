#!/bin/bash

print_warning() {
  echo -e "\033[1;33m$1\033[0m"
}
print_info() {
  echo -e "\033[1;32m$1\033[0m"
}

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

print_warning "===================================================================="
print_warning "                         WARNING                                     "
print_warning "   This script will run kernel-level BPF programs.                   "
print_warning "   BPF programs run with kernel privileges and could potentially     "
print_warning "   affect system stability if not used properly.                     "
print_warning "                                                                     "
print_warning "   This is a non-interactive version for curl piping.                "
print_warning "   The script will proceed automatically with installation.          "
print_warning "===================================================================="
echo

print_info "This script will:"
echo "1. Check and install required dependencies (libelf, clang, python, bpftool)"
echo "2. Download example programs from the Python-BPF GitHub repository"
echo "3. Create a Python virtual environment with necessary packages"
echo "4. Set up a Jupyter notebook server"
echo "Starting in 5 seconds. Press Ctrl+C to cancel..."
sleep 5

WORK_DIR="/tmp/python_bpf_setup"
REAL_USER=$(logname || echo "$SUDO_USER")

echo "Creating temporary directory: $WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR" || exit 1

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "Cannot determine Linux distribution. Exiting."
    exit 1
fi

install_dependencies() {
    case $DISTRO in
        ubuntu|debian|pop|mint|elementary|zorin)
            echo "Detected Ubuntu/Debian-based system"
            apt update

            # Check and install libelf
            if ! dpkg -l libelf-dev >/dev/null 2>&1; then
                echo "Installing libelf-dev..."
                apt install -y libelf-dev
            else
                echo "libelf-dev is already installed."
            fi

            # Check and install clang
            if ! command -v clang >/dev/null 2>&1; then
                echo "Installing clang..."
                apt install -y clang
            else
                echo "clang is already installed."
            fi

            # Check and install python
            if ! command -v python3 >/dev/null 2>&1; then
                echo "Installing python3..."
                apt install -y python3 python3-pip python3-venv
            else
                echo "python3 is already installed."
            fi

            # Check and install bpftool
            if ! command -v bpftool >/dev/null 2>&1; then
                echo "Installing bpftool..."
                apt install -y linux-tools-common linux-tools-generic

                # If bpftool still not found, try installing linux-tools-$(uname -r)
                if ! command -v bpftool >/dev/null 2>&1; then
                    KERNEL_VERSION=$(uname -r)
                    apt install -y linux-tools-$KERNEL_VERSION
                fi
            else
                echo "bpftool is already installed."
            fi
            ;;

        arch|manjaro|endeavouros)
            echo "Detected Arch-based Linux system"

            # Check and install libelf
            if ! pacman -Q libelf >/dev/null 2>&1; then
                echo "Installing libelf..."
                pacman -S --noconfirm libelf
            else
                echo "libelf is already installed."
            fi

            # Check and install clang
            if ! command -v clang >/dev/null 2>&1; then
                echo "Installing clang..."
                pacman -S --noconfirm clang
            else
                echo "clang is already installed."
            fi

            # Check and install python
            if ! command -v python3 >/dev/null 2>&1; then
                echo "Installing python3..."
                pacman -S --noconfirm python python-pip
            else
                echo "python3 is already installed."
            fi

            # Check and install bpftool
            if ! command -v bpftool >/dev/null 2>&1; then
                echo "Installing bpftool..."
                pacman -S --noconfirm bpf linux-headers
            else
                echo "bpftool is already installed."
            fi
            ;;

        *)
            echo "Unsupported distribution: $DISTRO"
            echo "This script only supports Ubuntu/Debian and Arch Linux derivatives."
            exit 1
            ;;
    esac
}

echo "Checking and installing dependencies..."
install_dependencies

# Download example programs
echo "Downloading example programs from Python-BPF GitHub repository..."
mkdir -p examples
cd examples || exit 1

echo "Fetching example files list..."
FILES=$(curl -s "https://api.github.com/repos/pythonbpf/Python-BPF/contents/examples" | grep -E -o '"path": "examples/[^"]*(\.md|\.ipynb|\.py)"' | awk -F'"' '{print $4}')
BCC_EXAMPLES=$(curl -s "https://api.github.com/repos/pythonbpf/Python-BPF/contents/BCC-Examples" | grep -E -o '"path": "BCC-Examples/[^"]*(\.md|\.ipynb|\.py)"' | awk -F'"' '{print $4}')

if [ -z "$FILES" ]; then
    echo "Failed to fetch file list from repository. Using fallback method..."
    # Fallback to downloading common example files
    EXAMPLES=(
        "binops_demo.py"
        "blk_request.py"
        "clone-matplotlib.ipynb"
        "clone_plot.py"
        "hello_world.py"
        "kprobes.py"
        "struct_and_perf.py"
        "sys_sync.py"
        "xdp_pass.py"
    )

    for example in "${EXAMPLES[@]}"; do
        echo "Downloading: $example"
        curl -s -O "https://raw.githubusercontent.com/pythonbpf/Python-BPF/master/examples/$example"
    done
else
    mkdir examples && cd examples
    for file in $FILES; do
        filename=$(basename "$file")
        echo "Downloading: $filename"
        curl -s -o "$filename" "https://raw.githubusercontent.com/pythonbpf/Python-BPF/master/$file"
    done
    cd ..
    mkdir BCC-Examples && cd BCC-Examples
    for file in $BCC_EXAMPLES; do
        filename=$(basename "$file")
        echo "Downloading: $filename"
        curl -s -o "$filename" "https://raw.githubusercontent.com/pythonbpf/Python-BPF/master/$file"
    done
    cd ..
fi

cd "$WORK_DIR" || exit 1
chown -R "$REAL_USER:$(id -gn "$REAL_USER")" .

echo "Creating Python virtual environment..."
su - "$REAL_USER" -c "cd \"$WORK_DIR\" && python3 -m venv venv"

echo "Installing Python packages..."
su - "$REAL_USER" -c "cd \"$WORK_DIR\" && source venv/bin/activate && pip install --upgrade pip && pip install jupyter pythonbpf pylibbpf matplotlib"

cat > "$WORK_DIR/start_jupyter.sh" << EOF
#!/bin/bash
cd "$WORK_DIR"
source venv/bin/activate
cd examples
sudo ../venv/bin/python -m notebook --ip=0.0.0.0 --allow-root
EOF

chmod +x "$WORK_DIR/start_jupyter.sh"
chown "$REAL_USER:$(id -gn "$REAL_USER")" "$WORK_DIR/start_jupyter.sh"

print_info "========================================================"
print_info "Setup complete! To start Jupyter Notebook, run:"
print_info "$ sudo $WORK_DIR/start_jupyter.sh"
print_info "========================================================"
