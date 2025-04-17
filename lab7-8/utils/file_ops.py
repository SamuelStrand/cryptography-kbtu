def save_to_file(file_path, data):
    with open(file_path, "w") as f:
        f.write(data)

def load_from_file(file_path):
    with open(file_path, "r") as f:
        return f.read()
