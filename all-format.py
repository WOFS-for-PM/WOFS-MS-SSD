import os

def format_files_in_directories(directories):
    c_and_h_extensions = (".c", ".h")
    
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(c_and_h_extensions):
                    file_path = os.path.join(root, file)
                    os.system(f"clang-format -i -style=file {file_path}")
                    print(f"Formatted: {file_path}")

# Replace the list with the paths to the directories you want to format
directories_to_format = ["./"]
format_files_in_directories(directories_to_format)