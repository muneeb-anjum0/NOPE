import zipfile


def unpack(upload_path, destination):
    with zipfile.ZipFile(upload_path) as archive:
        archive.extractall(destination)
