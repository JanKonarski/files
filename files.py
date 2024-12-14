import os
import sys
import uuid
import json
import mimetypes
import lief


def analyze_file(filepath):
    """Return dictionary od file information"""
    file_info = {
        "uuid": str(uuid.uuid4()),
        "name": os.path.basename(filepath),
        "mime": mimetypes.guess_type(filepath)[0] or "unknown",
        "executable": False,
        "architecture": None,
        "os": None
    }

    # binary analysis
    try:
        binary = lief.parse(filepath)
        if binary:
            file_info["executable"] = True
            file_info["architecture"] = str(binary.header.machine_type)
            file_info["os"] = binary.format.name.lower()
    except:
        pass

    return file_info


def process_directory(directory, output_directory):
    """Process directory and create JSON description file"""
    metadata = []
    directory_name = os.path.basename(directory)

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            metadata.append(analyze_file(filepath))

    output_file = os.path.join(output_directory, f"{directory_name}.json")
    with open(output_file, "w", encoding="utf-8") as json_file:
        json.dump(metadata, json_file, indent=4)
    print(f"Saved JSON file: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Use: python3 script.py <path>")
        sys.exit(1)

    base_directory = sys.argv[1]
    if not os.path.isdir(base_directory):
        sys.exit(1)

    output_directory = os.getcwd()

    for subdir in os.listdir(base_directory):
        subdir_path = os.path.join(base_directory, subdir)
        if os.path.isdir(subdir_path):
            print(f"Processing directory: {subdir_path}")
            process_directory(subdir_path, output_directory)