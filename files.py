import os
import sys
import uuid
import json
#import mimetypes
#import lief
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

class FileAnalyzer:
    def analyze(self, filepath):
        """Analyze file by running 'file' command."""
        try:
            result = subprocess.run(
                ["file", "-b", filepath],
                text=True,
                capture_output=True,
                check=True
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"Error analyzing file {filepath}: {e}")
            return None

    def analyze_mime(self, filepath):
        """Analyze file mime type."""
        try:
            result = subprocess.run(
                ["file", "--mime-type", "-b", filepath],
                text=True,
                capture_output=True,
                check=True
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"Error analyzing file {filepath}: {e}")
            return None

    def close(self):
        """Terminate the 'file' process."""
        if self.process:
            self.process.stdin.close()
            self.process.terminate()
            self.process.wait()

        if self.process_mime:
            self.process_mime.stdin.close()
            self.process_mime.terminate()
            self.process_mime.wait()

def analyze_file(filepath, file_analyzer):
    """Return dictionary od file information"""
    file_info = {
        "uuid": str(uuid.uuid4()),
        "name": os.path.basename(filepath),
        "mime": "unknown",
        "result": None,
        "size_b": None
    }

    # binary analysis
    try:
        file_info["result"] = file_analyzer.analyze(filepath)
        file_info["mime"] = file_analyzer.analyze_mime(filepath)
        file_size_bytes = os.path.getsize(filepath)
        file_info["size_b"] = (file_size_bytes + 1023)
    except Exception as e:
        print(e)
        pass

    return file_info


def process_directory(directory, output_directory, file_analyzer, max_threads=4):
    """Process directory with multithreading and create JSON description file."""
    metadata = []
    directory_name = os.path.basename(directory)

    # Get the list of files in the directory
    filepaths = [
        os.path.join(root, file)
        for root, _, files in os.walk(directory)
        for file in files
    ]

    # Use ThreadPoolExecutor to process files in parallel
    with ThreadPoolExecutor(max_threads) as executor:
        future_to_file = {
            executor.submit(analyze_file, filepath, file_analyzer): filepath
            for filepath in filepaths
        }

        for future in as_completed(future_to_file):
            try:
                file_info = future.result()
                metadata.append(file_info)
            except Exception as e:
                print(f"Error processing file: {e}")

    output_file = os.path.join(output_directory, f"{directory_name}.json")
    with open(output_file, "w", encoding="utf-8") as json_file:
        json.dump(metadata, json_file, indent=4)
    print(f"Saved JSON file: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Use: python3 script.py <path>")
        sys.exit(1)

    base_directory = sys.argv[1]
    max_threads = int(sys.argv[2])

    if not os.path.isdir(base_directory):
        print(f"Error: {base_directory} is not a valid directory.")
        sys.exit(1)

    output_directory = os.getcwd()

    # Initialize the persistent file analyzer
    file_analyzer = FileAnalyzer()

    try:
        for subdir in os.listdir(base_directory):
            subdir_path = os.path.join(base_directory, subdir)
            if os.path.isdir(subdir_path):
                print(f"Processing directory: {subdir_path} with {max_threads} threads")
                process_directory(subdir_path, output_directory, file_analyzer, max_threads)
    finally:
        # Ensure the file analyzer process is closed
        file_analyzer.close()