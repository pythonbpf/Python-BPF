#!/usr/bin/env python3
"""
BTF to Python ctypes Converter
Converts Linux kernel BTF (BPF Type Format) to Python ctypes definitions.

This tool automates the process of:
1. Dumping BTF from vmlinux
2. Preprocessing enum definitions
3. Processing struct kioctx to extract anonymous nested structs
4. Running C preprocessor
5. Converting to Python ctypes using clang2py
6. Post-processing the output

Requirements:
- bpftool
- clang
- ctypeslib2 (pip install ctypeslib2)
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile


class BTFConverter:
    def __init__(
        self,
        btf_source="/sys/kernel/btf/vmlinux",
        output_file="vmlinux.py",
        keep_intermediate=False,
        verbose=False,
    ):
        self.btf_source = btf_source
        self.output_file = output_file
        self.keep_intermediate = keep_intermediate
        self.verbose = verbose
        self.temp_dir = tempfile.mkdtemp() if not keep_intermediate else "."

    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")

    def run_command(self, cmd, description):
        """Run a shell command and handle errors."""
        self.log(f"{description}...")
        try:
            result = subprocess.run(
                cmd, shell=True, check=True, capture_output=True, text=True
            )
            if self.verbose and result.stdout:
                print(result.stdout)
            return result
        except subprocess.CalledProcessError as e:
            print(f"Error during {description}:", file=sys.stderr)
            print(e.stderr, file=sys.stderr)
            sys.exit(1)

    def step1_dump_btf(self):
        """Step 1: Dump BTF from vmlinux."""
        vmlinux_h = os.path.join(self.temp_dir, "vmlinux.h")
        cmd = f"bpftool btf dump file {self.btf_source} format c > {vmlinux_h}"
        self.run_command(cmd, "Dumping BTF from vmlinux")
        return vmlinux_h

    def step2_preprocess_enums(self, input_file):
        """Step 1.5: Preprocess enum definitions."""
        self.log("Preprocessing enum definitions...")

        with open(input_file, "r") as f:
            original_code = f.read()

        # Extract anonymous enums
        enums = re.findall(
            r"(?<!typedef\s)(enum\s*\{[^}]*\})\s*(\w+)\s*(?::\s*\d+)?\s*;",
            original_code,
        )
        enum_defs = [enum_block + ";" for enum_block, _ in enums]

        # Replace anonymous enums with int declarations
        processed_code = re.sub(
            r"(?<!typedef\s)enum\s*\{[^}]*\}\s*(\w+)\s*(?::\s*\d+)?\s*;",
            r"int \1;",
            original_code,
        )

        # Prepend enum definitions
        if enum_defs:
            enum_text = "\n".join(enum_defs) + "\n\n"
            processed_code = enum_text + processed_code

        output_file = os.path.join(self.temp_dir, "vmlinux_processed.h")
        with open(output_file, "w") as f:
            f.write(processed_code)

        return output_file

    def step2_5_process_kioctx(self, input_file):
        # TODO: this is a very bad bug and design decision. A single struct has an issue mostly.
        """Step 2.5: Process struct kioctx to extract nested anonymous structs."""
        self.log("Processing struct kioctx nested structs...")

        with open(input_file, "r") as f:
            content = f.read()

        # Pattern to match struct kioctx with its full body (handles multiple nesting levels)
        kioctx_pattern = (
            r"struct\s+kioctx\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}\s*;"
        )

        def process_kioctx_replacement(match):
            full_struct = match.group(0)
            self.log(f"Found struct kioctx, length: {len(full_struct)} chars")

            # Extract the struct body (everything between outermost { and })
            body_match = re.search(
                r"struct\s+kioctx\s*\{(.*)\}\s*;", full_struct, re.DOTALL
            )
            if not body_match:
                return full_struct

            body = body_match.group(1)

            # Find all anonymous structs within the body
            # Pattern: struct { ... } followed by ; (not a member name)
            # anon_struct_pattern = r"struct\s*\{[^}]*\}"

            anon_structs = []
            anon_counter = 4  # Start from 4, counting down to 1

            def replace_anonymous_struct(m):
                nonlocal anon_counter
                anon_struct_content = m.group(0)

                # Extract the body of the anonymous struct
                anon_body_match = re.search(
                    r"struct\s*\{(.*)\}", anon_struct_content, re.DOTALL
                )
                if not anon_body_match:
                    return anon_struct_content

                anon_body = anon_body_match.group(1)

                # Create the named struct definition
                anon_name = f"__anon{anon_counter}"
                member_name = f"a{anon_counter}"

                # Store the struct definition
                anon_structs.append(f"struct {anon_name} {{{anon_body}}};")

                anon_counter -= 1

                # Return the member declaration
                return f"struct {anon_name} {member_name}"

            # Process the body, finding and replacing anonymous structs
            # We need to be careful to only match anonymous structs followed by ;
            processed_body = body

            # Find all occurrences and process them
            pattern_with_semicolon = r"struct\s*\{([^}]*)\}\s*;"
            matches = list(re.finditer(pattern_with_semicolon, body, re.DOTALL))

            if not matches:
                self.log("No anonymous structs found in kioctx")
                return full_struct

            self.log(f"Found {len(matches)} anonymous struct(s)")

            # Process in reverse order to maintain string positions
            for match in reversed(matches):
                anon_struct_content = match.group(1)
                start_pos = match.start()
                end_pos = match.end()

                # Create the named struct definition
                anon_name = f"__anon{anon_counter}"
                member_name = f"a{anon_counter}"

                # Store the struct definition
                anon_structs.insert(0, f"struct {anon_name} {{{anon_struct_content}}};")

                # Replace in the body
                replacement = f"struct {anon_name} {member_name};"
                processed_body = (
                    processed_body[:start_pos] + replacement + processed_body[end_pos:]
                )

                anon_counter -= 1

            # Rebuild the complete definition
            if anon_structs:
                # Prepend the anonymous struct definitions
                anon_definitions = "\n".join(anon_structs) + "\n\n"
                new_struct = f"struct kioctx {{{processed_body}}};"
                return anon_definitions + new_struct
            else:
                return full_struct

        # Apply the transformation
        processed_content = re.sub(
            kioctx_pattern, process_kioctx_replacement, content, flags=re.DOTALL
        )

        output_file = os.path.join(self.temp_dir, "vmlinux_kioctx_processed.h")
        with open(output_file, "w") as f:
            f.write(processed_content)

        self.log(f"Saved kioctx-processed output to {output_file}")
        return output_file

    def step3_run_preprocessor(self, input_file):
        """Step 2: Run C preprocessor."""
        output_file = os.path.join(self.temp_dir, "vmlinux.i")
        cmd = f"clang -E {input_file} > {output_file}"
        self.run_command(cmd, "Running C preprocessor")
        return output_file

    def step4_convert_to_ctypes(self, input_file):
        """Step 3: Convert to Python ctypes using clang2py."""
        output_file = os.path.join(self.temp_dir, "vmlinux_raw.py")
        cmd = (
            f"clang2py {input_file} -o {output_file} "
            f'--clang-args="-fno-ms-extensions -I/usr/include -I/usr/include/linux"'
        )
        self.run_command(cmd, "Converting to Python ctypes")
        return output_file

    def step5_postprocess(self, input_file):
        """Step 4: Post-process the generated Python file."""
        self.log("Post-processing Python ctypes definitions...")

        with open(input_file, "r") as f:
            data = f.read()

        # Remove lines like ('_45', ctypes.c_int64, 0)
        data = re.sub(r"\('_[0-9]+',\s*ctypes\.[a-zA-Z0-9_]+,\s*0\),?\s*\n?", "", data)

        # Replace ('_20', ctypes.c_uint64, 64) → ('_20', ctypes.c_uint64)
        data = re.sub(
            r"\('(_[0-9]+)',\s*(ctypes\.[a-zA-Z0-9_]+),\s*[0-9]+\)", r"('\1', \2)", data
        )

        # Replace ('_20', ctypes.c_char, 8) with ('_20', ctypes.c_uint8, 8)
        data = re.sub(r"(ctypes\.c_char)(\s*,\s*\d+\))", r"ctypes.c_uint8\2", data)

        # Some bitfields come out of clang2py with a declared width that
        # exceeds their own base type's bit width (e.g. a 15-bit field typed
        # as ctypes.c_ubyte, which only has 8 bits) - ctypes rejects these
        # outright with "ValueError: number of bits invalid for bit field".
        # Widen the base type to the smallest standard integer type that can
        # actually hold the declared width.
        bitfield_type_widths = {
            "c_bool": 8,
            "c_byte": 8,
            "c_ubyte": 8,
            "c_int8": 8,
            "c_uint8": 8,
            "c_short": 16,
            "c_ushort": 16,
            "c_int16": 16,
            "c_uint16": 16,
            "c_int": 32,
            "c_uint": 32,
            "c_int32": 32,
            "c_uint32": 32,
            "c_long": 64,
            "c_ulong": 64,
            "c_longlong": 64,
            "c_ulonglong": 64,
            "c_int64": 64,
            "c_uint64": 64,
        }
        promoted_type_for_width = {
            8: "c_uint8",
            16: "c_uint16",
            32: "c_uint32",
            64: "c_uint64",
        }

        def widen_oversized_bitfields(m):
            name, base_type, bits = m.group(1), m.group(2), int(m.group(3))
            type_width = bitfield_type_widths.get(base_type)
            if type_width is None or bits <= type_width:
                return m.group(0)
            for width in (8, 16, 32, 64):
                if bits <= width:
                    return (
                        f"('{name}', ctypes.{promoted_type_for_width[width]}, {bits})"
                    )
            return m.group(0)

        data = re.sub(
            r"\('([^']+)',\s*ctypes\.([a-zA-Z0-9_]+),\s*(\d+)\)",
            widen_oversized_bitfields,
            data,
        )

        # Remove ctypes. prefix from invalid entries
        invalid_ctypes = ["bpf_iter_state", "_cache_type", "fs_context_purpose"]
        for name in invalid_ctypes:
            data = re.sub(rf"\bctypes\.{name}\b", name, data)

        data = self.disambiguate_anonymous_field_names(data)

        with open(self.output_file, "w") as f:
            f.write(data)

        self.log(f"Saved final output to {self.output_file}")

    def disambiguate_anonymous_field_names(self, data):
        """Make clang2py's generic '_N' field names globally unique per struct/union.

        clang2py names both (a) unnamed anonymous struct/union members that go
        into `_anonymous_`, and (b) other unnamed/reserved members, using the
        same per-struct sequential scheme ('_0', '_1', ...). ctypes flattens
        anonymous members by promoting their field names onto the parent class,
        so if a struct has an anonymous member (say '_0') whose type itself has
        a field also named '_1', and that same struct has ANOTHER anonymous
        member named '_1', the promoted name collides with the parent's own
        field key. ctypes then fails with a cryptic
        "type object 'c_ulong' has no attribute '_fields_'" (or similar) when
        `_fields_` is assigned. Prefixing every generic '_N' key with its
        owning struct/union name keeps these names unique across the whole
        file, so promoted names can never collide with a sibling's own key.
        """
        self.log("Disambiguating generic anonymous-field names...")

        def sanitize(name):
            return re.sub(r"[^0-9A-Za-z_]", "_", name)

        lines = data.split("\n")
        class_re = re.compile(r"^class\s+(\w+)\(")
        stmt_fields_re = re.compile(r"^(\w+)\._fields_\s*=\s*\[\s*$")
        inline_fields_re = re.compile(r"^\s+_fields_\s*=\s*\[\s*$")
        anon_stmt_re = re.compile(r"^(\w+)\._anonymous_\s*=\s*\((.*)\)\s*$")
        anon_inline_re = re.compile(r"^(\s+)_anonymous_\s*=\s*\((.*)\)\s*$")
        key_re = re.compile(r"(\('_)([0-9]+)(',)")

        last_class = None
        out = []
        i = 0
        n = len(lines)
        renamed_count = 0
        while i < n:
            line = lines[i]

            m_class = class_re.match(line)
            if m_class:
                last_class = m_class.group(1)
                out.append(line)
                i += 1
                continue

            m_anon = anon_stmt_re.match(line)
            if m_anon:
                cls, body = m_anon.group(1), m_anon.group(2)
                prefix = sanitize(cls)
                new_body, cnt = re.subn(
                    r"'_([0-9]+)'", lambda mm: f"'_{prefix}_{mm.group(1)}'", body
                )
                renamed_count += cnt
                out.append(f"{cls}._anonymous_ = ({new_body})")
                i += 1
                continue

            m_anon_inline = anon_inline_re.match(line)
            if m_anon_inline and last_class:
                indent, body = m_anon_inline.group(1), m_anon_inline.group(2)
                prefix = sanitize(last_class)
                new_body, cnt = re.subn(
                    r"'_([0-9]+)'", lambda mm: f"'_{prefix}_{mm.group(1)}'", body
                )
                renamed_count += cnt
                out.append(f"{indent}_anonymous_ = ({new_body})")
                i += 1
                continue

            m_stmt = stmt_fields_re.match(line)
            m_inline = inline_fields_re.match(line) if not m_stmt else None
            if m_stmt or m_inline:
                cls = m_stmt.group(1) if m_stmt else last_class
                prefix = sanitize(cls) if cls else None
                out.append(line)
                i += 1
                while i < n and lines[i].strip() != "]":
                    fl = lines[i]
                    if prefix:
                        fl, cnt = key_re.subn(
                            lambda mm: f"{mm.group(1)}{prefix}_{mm.group(2)}{mm.group(3)}",
                            fl,
                        )
                        renamed_count += cnt
                    out.append(fl)
                    i += 1
                if i < n:
                    out.append(lines[i])  # closing ']'
                    i += 1
                continue

            out.append(line)
            i += 1

        self.log(f"Renamed {renamed_count} generic field keys")
        return "\n".join(out)

    def cleanup(self):
        """Remove temporary files if not keeping them."""
        if not self.keep_intermediate and self.temp_dir != ".":
            self.log(f"Cleaning up temporary directory: {self.temp_dir}")
            import shutil

            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def convert(self):
        """Run the complete conversion pipeline."""
        try:
            self.log("Starting BTF to Python ctypes conversion...")

            # Check dependencies
            self.check_dependencies()

            # Run conversion pipeline
            vmlinux_h = self.step1_dump_btf()
            vmlinux_processed_h = self.step2_preprocess_enums(vmlinux_h)
            vmlinux_kioctx_h = self.step2_5_process_kioctx(vmlinux_processed_h)
            vmlinux_i = self.step3_run_preprocessor(vmlinux_kioctx_h)
            vmlinux_raw_py = self.step4_convert_to_ctypes(vmlinux_i)
            self.step5_postprocess(vmlinux_raw_py)

            print(f"\n✓ Conversion complete! Output saved to: {self.output_file}")

        except Exception as e:
            print(f"\n✗ Error during conversion: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc()
            sys.exit(1)
        finally:
            self.cleanup()

    def check_dependencies(self):
        """Check if required tools are available."""
        self.log("Checking dependencies...")

        dependencies = {
            "bpftool": "bpftool --version",
            "clang": "clang --version",
            "clang2py": "clang2py --version",
        }

        missing = []
        for tool, cmd in dependencies.items():
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError:
                missing.append(tool)

        if missing:
            print("Error: Missing required dependencies:", file=sys.stderr)
            for tool in missing:
                print(f"  - {tool}", file=sys.stderr)
            if "clang2py" in missing:
                print("\nInstall ctypeslib2: pip install ctypeslib2", file=sys.stderr)
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Convert Linux kernel BTF to Python ctypes definitions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s -o kernel_types.py
  %(prog)s --btf-source /sys/kernel/btf/custom_module -k -v
        """,
    )

    parser.add_argument(
        "--btf-source",
        default="/sys/kernel/btf/vmlinux",
        help="Path to BTF source (default: /sys/kernel/btf/vmlinux)",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="vmlinux.py",
        help="Output Python file (default: vmlinux.py)",
    )

    parser.add_argument(
        "-k",
        "--keep-intermediate",
        action="store_true",
        help="Keep intermediate files (vmlinux.h, vmlinux_processed.h, etc.)",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    converter = BTFConverter(
        btf_source=args.btf_source,
        output_file=args.output,
        keep_intermediate=args.keep_intermediate,
        verbose=args.verbose,
    )

    converter.convert()


if __name__ == "__main__":
    main()
