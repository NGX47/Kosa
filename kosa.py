import lzma
import gzip
import zlib

from enum import Enum
import fnmatch
import os
import struct

import hashlib

#region: Exceptions
class FailureException(Exception): ...
class UnrecognizedCompressionAlgorithm(FailureException): ...
class NotFileExists(FailureException): ...
class NotDirectoryExists(FailureException): ...
class NoEntry(Exception): ...
class InvalidPathValue(Exception): ...
class IncorrectEncryptionStrategy(Exception): ...
class ReadOutOfBound(Exception): ...
class BackTooMuch(Exception): ...
class NotArchive(Exception): ...
class RequireEncryptor(Exception): ...
class ReadHeadFailure(FailureException): ...
class NoByteToRead(Exception): ...



class InvalidPasswordException(Exception): ...
#endregion: Exceptions



class Scan:
    def __init__(self, directory:str) -> None:
        if not os.path.exists(directory) or not os.path.isdir(directory):
            raise NotDirectoryExists(f"Path \"{directory}\" not exists.") 
        
        self.directory = directory

    def run(self) -> list[str]:
        file_paths = list[str]()
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.relpath(os.path.join(root, file), self.directory)
                file_paths.append(file_path)
        return file_paths

    def ignores(self, patterns: list[str]) -> list[str]:
        file_paths = list[str]()
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.relpath(os.path.join(root, file), self.directory)
                if not any(fnmatch.fnmatch(file_path, pattern) for pattern in patterns):
                    file_paths.append(file_path)
        return file_paths
    
    def includes(self, patterns: list[str]) -> list[str]:
        file_paths = list[str]()
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.relpath(os.path.join(root, file), self.directory)
                if any(fnmatch.fnmatch(file_path, pattern) for pattern in patterns):
                    file_paths.append(file_path)
        return file_paths



class Algorithms(Enum):
    """
    Enum for compression algorithms
    """
    LZMA = "LZMA"
    GZIP = "GZIP"
    ZLIB = "ZLIB"

    @staticmethod
    def from_string(value: str) -> 'Algorithms':
        """
        Get algoritm from string

        Args:
            value (str): string representation

        Raises:
            UnrecognizedCompressionAlgorithm: when unrecognized algorithm is given.

        Returns:
            Algorithms: the algorithm
        """
        t = value.strip().upper()
        for algorithm in Algorithms:
            if t == algorithm.value:
                return algorithm
        raise UnrecognizedCompressionAlgorithm(f"Unrecognized Algorithm: {value}")
    


#region:encryption
class IEncryption:
    """
    Abstract Class for Encryption
    """
    def __init__(self) -> None:
        raise NotImplementedError

    def encrypt(self, data:bytes) -> bytes:
        raise NotImplementedError
    
    def decrypt(self, data:bytes) -> bytes:
        raise NotImplementedError
    
class PasswordEncryption(IEncryption):
    def __init__(self, passwd:str) -> None:
        self.passwd = passwd
    
    def encrypt(self, data: bytes) -> bytes:
        byte = list[bytes]()

        pswd = hashlib.sha512(self.passwd.encode(encoding="utf-8")).digest()
        pswd = struct.pack("<I", len(pswd)) + pswd

        byte.append(pswd)
        byte.append(data)

        return b"".join(byte)
    
    def decrypt(self, data: bytes) -> bytes:
        pswd_length = struct.unpack("<I", data[:4])[0]
        pswd = data[4 : 4 + pswd_length]
        data = data[4 + pswd_length:]

        hashed_pswd = hashlib.sha512(self.passwd.encode(encoding="utf-8")).digest()

        if pswd != hashed_pswd:
            raise InvalidPasswordException("Invalid password.")

        return data
#endregion:encryption



def _decompress(data:bytes, algorithm:Algorithms) -> bytes:
    if algorithm == Algorithms.LZMA:
        data = lzma.decompress(data)
    elif algorithm == Algorithms.GZIP:
        data = gzip.decompress(data)
    elif algorithm == Algorithms.ZLIB:
        data = zlib.decompress(data)
    else:
        raise UnrecognizedCompressionAlgorithm(f"Unrecognized Algorithm: {algorithm}")
    return data

def _compress(data:bytes, algorithm:Algorithms) -> bytes:
    if algorithm == Algorithms.LZMA:
        data = lzma.compress(data)
    elif algorithm == Algorithms.GZIP:
        data = gzip.compress(data)
    elif algorithm == Algorithms.ZLIB:
        data = zlib.compress(data)
    else:
        raise UnrecognizedCompressionAlgorithm(f"Unrecognized Algorithm: {algorithm}")
    return data



def _path_check(path:str) -> bool:
    return not (path.startswith("/") or path.startswith("./") or path.startswith("../"))



class Entry:
    def __init__(self, path: str, data: bytes, compressed: bool, algorithm: Algorithms, crc: int = 0, comment: str = "", permission: str = "664") -> None:
        """
        Class for file entry.

        Args:
            path (str): path of the file, eg `dir/Hello World.txt`.
            data (bytes): data of the file.
            compressed (bool): wether the `data` argument is compressed or not.
            algorithm (Algorithms): algorithm used to compress.
            crc (int, optional): CRC value of (Uncompressed) `data` argument, if not given it will be calculated.
            comment (str, optional): comments of the entry. Defaults to "".
            permission (str, optional): octal permission code. Defaults to "664".

        Raises:
            UnrecognizedCompressionAlgorithm: Raised when unrecognized compression algorithm is given.
        """

        if algorithm not in Algorithms:
            raise UnrecognizedCompressionAlgorithm(f"Unrecognized Algorithm: {algorithm}")

        self.path = path.strip()
        self.algorithm = algorithm
        if compressed:
            # Uncompress it.
            self.data = _decompress(data, algorithm)
            self.compressed = False
        else:
            self.data = data
            self.compressed = False
        
        if crc == 0:
            self.crc = zlib.crc32(self.data)
        else:
            self.crc = crc

        self.comment = comment.strip()
        self.permission = permission.strip()
        if len(self.permission) != 3 or any(not char.isdigit() for char in self.permission):
            self.permission = "664"



    def compress(self, set_self: bool = False) -> bytes:
        """
        compress the file

        Args:
            set_self (bool, optional): Mark entry as compressed after compression. Defaults to False.

        Raises:
            UnrecognizedCompressionAlgorithm: Raised when unrecognized compression algorithm is given.

        Returns:
            bytes: compressed data.
        """
        data = self.data
        if self.compressed:
            return data
        
        data = _compress(data, self.algorithm)
        
        if set_self:
            self.compressed = True
            self.data = data
        return data
        


    def decompress(self, set_self: bool = False) -> bytes:
        """
        decompress the file

        Args:
            set_self (bool, optional): Mark entry as decompressed after decompression. Defaults to False.

        Raises:
            UnrecognizedCompressionAlgorithm: Raised when unrecognized compression algorithm is given.

        Returns:
            bytes: decompressed data.
        """
        data = self.data

        if not self.compressed:
            return data
        
        data = _decompress(data, self.algorithm)
        
        if set_self:
            self.compressed = False
            self.data = data
        return data
    


    def get_compression(self) -> bytes:
        """
        Get the bytes representing the entry.

        Returns:
            bytes: entry info
        """
        data = self.compress()

        path = self.path.encode(encoding="utf-8")
        path = struct.pack("<I", len(path)) + path

        crc = self.crc
        crc = struct.pack("<I", crc)

        comment = self.comment.encode(encoding="utf-8")
        comment = struct.pack("<I", len(comment)) + comment

        permission = self.permission.encode(encoding="utf-8")
        permission = struct.pack("<3s", permission)

        size = len(data)
        size = struct.pack("<I", size)

        byte = list[bytes]()

        byte.append(path)
        byte.append(crc)
        byte.append(comment)
        byte.append(permission)
        byte.append(size)
        byte.append(data)
        return b"".join(byte)
    
    def get_data(self) -> bytes:
        """
        Get entry's data (Uncompressed)

        Returns:
            bytes: the data
        """
        data = self.decompress()
        return data
    


#region: KOSA
############################################################
#
#           KOSA
#
############################################################

class KosaArchiver:
    def __init__(self, author:str, algorithm:Algorithms|str) -> None:
        self.MAGIC_NUMBER = b"\x6B\x6F\x73\x61\x00\x0D\x0A"

        self.VERSION = 1
        
        self.encrypt = False # Wether to encrypt entries byte (AES).
        self.encryption = None



        #region: Checkings
        if isinstance(algorithm, str):
            algorithm = Algorithms.from_string(algorithm)
            
        if algorithm not in Algorithms:
            raise UnrecognizedCompressionAlgorithm(f"Unrecognized Algorithm: {algorithm}")
        
        #endregion: Checkings


        _author = author.strip()
        _author = _author.encode(encoding="utf-8")
        _author = struct.pack("<I", len(_author)) + _author
        self.AUTHOR = _author
        self.ALGORITHM = algorithm

        self.entries = list[Entry]()



    def set_encrypt_entries(self, encryption:IEncryption|None) -> None:
        if encryption is None:
            self.encryption = None
            self.encrypt = False
        else:
            self.encryption = encryption
            self.encrypt = True


    def sort(self) -> None:
        """
        Sort the entries list by path in ascending order.
        """
        self.entries.sort(key=lambda entry: entry.path)



    def scan(self, directory:str) -> None:
        scan = Scan(directory)
        files = scan.run()
        for x in files:
            if not _path_check(x):
                raise InvalidPathValue(x)
            
            with open(os.path.join(directory, x), "rb") as f:
                data = f.read()
            e = Entry(x, data, False, self.ALGORITHM)
            self.entries.append(e)

        self.sort()



    def add_file(self, path: str, path_as: str) -> None:
        """
        Add files to archive

        Args:
            path (str): path of file
            path_as (str): path of file in archive

        Raises:
            NotFileExists: _description_
        """

        if not _path_check(path_as):
            raise InvalidPathValue(path_as)
        
        if not os.path.exists(path) or os.path.isdir(path):
            raise NotFileExists(f"Path \"{path}\" not exists.")
        
        with open(path, "rb") as f:
            data = f.read()
        e = Entry(path_as, data, False, self.ALGORITHM)
        self.entries.append(e)
        self.sort()



    def remove_file(self, path:str) -> None:
        if not _path_check(path):
            raise InvalidPathValue(path)
        
        entries = list[Entry]()
        for x in self.entries:
            if x.path == path:
                continue
            entries.append(x)
        self.entries = entries
        self.sort()


    
    def get_entries_bytes(self) -> bytes:
        """
        Get entries bytes.

        Returns:
            bytes: the bytes.
        """
        self.sort()
        byte = list[bytes]()

        byte.append(struct.pack("<I", len(self.entries)))

        for x in self.entries:
            byte.append(x.get_compression())
        
        ebyte = b"".join(byte)

        if self.encryption:
            ebyte = self.encryption.encrypt(ebyte)

        return ebyte
    


    def get_head_bytes(self) -> bytes:
        """
        Get head bytes.

        Returns:
            bytes: the bytes.
        """
        byte = list[bytes]()
        
        version = struct.pack("<i", self.VERSION)
        encrypt = struct.pack("<?", self.encrypt)

        algorithm = str(self.ALGORITHM.value).encode()
        algorithm = struct.pack("<I", len(algorithm)) + algorithm


        
        byte.append(self.MAGIC_NUMBER)
        byte.append(version)
        byte.append(encrypt)
        byte.append(self.AUTHOR)
        byte.append(algorithm)

        return b"".join(byte)
    


    def get_bytes(self) -> bytes:
        """
        get bytes for writing archive

        Returns:
            bytes: the bytes
        """
        byte = list[bytes]()
        byte.append(self.get_head_bytes())
        byte.append(self.get_entries_bytes())
        return b"".join(byte)



class KosaDearchiver:
    def __init__(self, archive: bytes) -> None:
        self.archive_bytes = archive
        self.head_bytes = None
        self.entries_bytes = None
        self.entries_count = None

        self.MAGIC_NUMBER = b"\x6B\x6F\x73\x61\x00\x0D\x0A"

        offset = 0
        self.offset = offset

        self.algorithm = None

        self.head_readed = False
        self.head = dict[str, str|bool|int]()

        self.entries_readed = False
        self.entries = list[Entry]()
        
        magic = self.read(len(self.MAGIC_NUMBER))
        if magic != self.MAGIC_NUMBER:
            raise NotArchive
        self.read_head()

        ## Stuffs
        self.bytes_to_read:bytes|None = None
        self.byte_offset = 0



    def read(self, size: int) -> bytes:
        if self.offset + size > len(self.archive_bytes):
            raise ReadOutOfBound
        
        data = self.archive_bytes[self.offset:self.offset + size]
        self.offset += size
        return data
    
    def back(self, size:int) -> None:
        if self.offset - size < 0:
            raise BackTooMuch
        
        self.offset -= size
        return
    
    def read_bytes(self, size: int) -> bytes:
        if self.bytes_to_read is None:
            raise NoByteToRead
        
        if self.byte_offset + size > len(self.bytes_to_read):
            raise ReadOutOfBound
        
        data = self.bytes_to_read[self.byte_offset:self.byte_offset + size]
        self.byte_offset += size
        return data
    
    def back_bytes(self, size:int) -> None:
        if self.bytes_to_read is None:
            raise NoByteToRead
        
        if self.byte_offset - size < 0:
            raise BackTooMuch
        
        self.byte_offset -= size
        return



    def read_head(self) -> None:
        if self.head_readed:
            return
        
        version = struct.unpack("<i", self.read(4))[0]
        encrypt = struct.unpack("<?", self.read(1))[0]

        author_length = struct.unpack("<I", self.read(4))[0]
        author = self.read(author_length).decode(encoding="utf-8")

        algorithm_length = struct.unpack("<I", self.read(4))[0]
        algorithm = self.read(algorithm_length).decode(encoding="utf-8")

        
        self.head["version"] = int(version)
        self.head["encrypt"] = bool(encrypt)
        self.head["author"] = str(author)
        self.head["algorithm"] = str(algorithm)
        self.algorithm = Algorithms.from_string(str(algorithm))
        self.head_readed = True
        
        self.head_bytes = self.archive_bytes[:self.offset]



    def is_encrypted(self) -> bool:
        self.read_head()
        return bool(self.head["encrypt"])



    def read_entries(self, encryptor:IEncryption|None = None) -> None:
        self.read_head()

        if self.algorithm is None:
            raise ReadHeadFailure

        ebyte = self.archive_bytes[self.offset:]
        if self.is_encrypted():
            if encryptor is None:
                raise RequireEncryptor
            ebyte = encryptor.decrypt(ebyte)
        
        self.entries_bytes = ebyte
        self.bytes_to_read = ebyte

        entries_count = int(struct.unpack("<I", self.read_bytes(4))[0])
        self.entries_count = entries_count

        for _ in range(entries_count):
            length = struct.unpack("<I", self.read_bytes(4))[0]
            path = self.read_bytes(length).decode(encoding="utf-8")

            crc = struct.unpack("<I", self.read_bytes(4))[0]

            length = struct.unpack("<I", self.read_bytes(4))[0]
            comment = self.read_bytes(length).decode(encoding="utf-8")

            permission = str(struct.unpack("<3s", self.read_bytes(3))[0])


            length = struct.unpack("<I", self.read_bytes(4))[0]
            data = self.read_bytes(length)

            e = Entry(
                path=path,
                data=data,
                compressed=True,
                algorithm=self.algorithm,
                crc=crc,
                comment=comment,
                permission=permission
            )

            self.entries.append(e)

        self.entries_readed = True
        self.bytes_to_read = None
        self.byte_offset = 0

    def get_entries(self, encryptor:IEncryption|None = None) -> list[Entry]:
        """
        Get archive's entries

        Args:
            encryptor (IEncryption | None, optional): Encryptor used to encrypt the archive, see `IEncryption`. Defaults to None.
        """
        self.read_entries()
        return self.entries



class Kosa:
    @staticmethod
    def CreateArchiver(author:str, algorithm:Algorithms|str) -> KosaArchiver:
        return KosaArchiver(author, algorithm)
    
    @staticmethod
    def CreateDearchiver(archive: bytes) -> KosaDearchiver:
        return KosaDearchiver(archive)
    
    Algorithms = Algorithms

#endregion: KOSA
