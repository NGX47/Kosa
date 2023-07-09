# Kosa
###### A simple archiving library

# Know Issues
1. Use Lots of RAM when archiving large files.

# Usage
```py
from kosa import Kosa

# Creating
ach = Kosa.CreateArchiver("OwO Meow!", Kosa.Algorithms.GZIP)
ach.scan("path/to/folder/of/files")

with open("file.kosa", "wb") as f:
    print("getting archbyte")
    b = ach.get_bytes()
    print("writing archbyte")
    f.write(b)


# Reading

# Helper function
def ensurefile(fp: str) -> None:
    """
    Recursively creates a file

    Args:
        fp (str): Path to file

    Returns:
        None: None
    """
    if os.path.isfile(fp):
        return None

    directory = os.path.dirname(fp)
    os.makedirs(directory, exist_ok=True)

    with open(fp, 'x'):
        pass

with open("file.kosa", "rb") as f:
    data = f.read()

dch = Kosa.CreateDearchiver(data)
for x in dch.get_entries():
    print("===========================================")
    print(f"File: {x.path}")
    print(f"Comment: {x.comment}")
    print(f"Perm: {x.permission}")
    print(f"CRC: {x.crc}")
    path = os.path.join("datah", x.path)
    ensurefile(path)
    with open(path, "w+b") as f:
        f.write(x.get_data())
```
