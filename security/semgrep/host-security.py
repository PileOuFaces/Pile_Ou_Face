import shutil
import tarfile


def unsafe_extract(archive_path, destination):
    with tarfile.open(archive_path) as archive:
        # ruleid: pof.archive.unvalidated-extractall
        archive.extractall(destination)
    # ruleid: pof.archive.unvalidated-extractall
    shutil.unpack_archive(archive_path, destination)
