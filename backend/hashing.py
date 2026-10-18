import hashlib


def calculate_sha256(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            for block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(block)

        return sha256_hash.hexdigest()

    except FileNotFoundError:
        return None

    except PermissionError:
        return None


if __name__ == "__main__":

    file_path = "test_evidence.txt"

    hash_value = calculate_sha256(file_path)

    print("File:", file_path)
    print("SHA-256:", hash_value)