import argparse
import hashlib
import struct
import zlib
import binascii
import io

OBJ_OFS_DELTA = "OBJ_OFS_DELTA"
OBJ_REF_DELTA = "OBJ_REF_DELTA"
OBJ_TREE = "OBJ_TREE"
OBJ_COMMIT = "OBJ_COMMIT"
OBJ_BLOB = "OBJ_BLOB"
OBJ_TAG = "OBJ_TAG"
OBJ_TYPES = {
    1 : OBJ_COMMIT,
    2 : OBJ_TREE,
    3 : OBJ_BLOB,
    4 : OBJ_TAG,
    6 : OBJ_OFS_DELTA,
    7 : OBJ_REF_DELTA
}


class Header:
    def __init__(self, magic, version, count):
        self.magic = magic
        self.version = version
        self.count = count

    def __str__(self):
        return str(self.__dict__)

def byte_to_bits(b):
    bits = []
    for i in range(8):
        bits.insert(0, b >> i & 1)
    return bits

def bytes_to_bits(bs):
    res = []
    for b in bs:
        res += byte_to_bits(b)
    return res

class Bitstream:
    def __init__(self, bs):
        self.bs = bs
        self.buffer = []
        self.index = 0

    def read(self, n):
        if len(self.buffer) < n:
            need = n - len(self.buffer)
            if need % 8 == 0:
                need_read = need // 8
            else:
                need_read = need // 8 + 1
            new_bs = self.bs.read(need_read)
            new_bits = bytes_to_bits(new_bs)
            self.buffer += new_bits
        res = self.buffer[:n]
        self.buffer = self.buffer[n:]
        self.index += n
        return res
    

def read_header(bs):
    magic = bs.read(4)
    assert magic == b"PACK" 
    version_b = bs.read(4)
    version = struct.unpack("!I", version_b)[0]
    count_b = bs.read(4)
    count = struct.unpack("!I", count_b)[0]
    return Header(magic, version, count)

def bits_to_num(bits):
    acc = 0
    power = 1
    for bit in reversed(bits):
        acc += bit*power
        power *= 2
    return acc

def read_size(bitstream, continuation, initial_size=4):
    initial = bitstream.read(initial_size)
    all_bits = initial
    while continuation:
        continuation = bitstream.read(1)[0]
        next_bits = bitstream.read(7)
        all_bits = next_bits + all_bits
    return bits_to_num(all_bits)

def read_ofs_size(bitstream, continuation, initial_size=7):
    initial = bitstream.read(initial_size)
    all_bits = initial
    s = 0
    while continuation:
        continuation = bitstream.read(1)[0]
        next_bits = bitstream.read(7)
        all_bits = all_bits + next_bits
        s = 2**7*s + 2**7
    return bits_to_num(all_bits) + s

def read_object(bs):
    bitstream = Bitstream(bs)
    pos = bs.tell()
    continuation = bitstream.read(1)[0]
    obj_type = OBJ_TYPES[bits_to_num(bitstream.read(3))]
    size = read_size(bitstream, continuation)

    data = {}
    # what to do next depends on the type
    if obj_type == "OBJ_REF_DELTA":
        base_obj  = bs.read(20)
        data["base_obj"] = base_obj
    elif obj_type == "OBJ_OFS_DELTA":
        bitstream = Bitstream(bs)
        c = bitstream.read(1)
        offset = read_ofs_size(bitstream, 1, 7)
        data["offset"] = offset
    else:
        pass
    data_raw = bs.read()
    decomp = zlib.decompressobj()
    data["compressed"] = decomp.decompress(data_raw)
    bs.seek(bs.tell()-len(decomp.unused_data))
    return (obj_type, size, data, pos)


def checksum(bs):
    # we're at the end!
    sha = bs.read()
    bs.seek(0)
    all_bs = bs.read()
    data = all_bs[:-20]
    sha_check = hashlib.sha1(data).digest()
    return sha, sha_check

def read_packfile(bs):
    # header
    header = read_header(bs)

    # objects
    objects = []
    for i in range(header.count):
        obj = read_object(bs)
        objects.append(obj)

    # checksum
    sha, sha_check = checksum(bs)
    return (header, objects, sha, sha_check)

def parse_tree(blob_tree):
    tree = []
    i = 0
    while i < len(blob_tree):
        perm = b""
        filename = b""
        obj_id = b""
        while bytes([blob_tree[i]]) != b" ":
            perm += bytes([blob_tree[i]])
            i += 1
        i += 1
        while bytes([blob_tree[i]]) != b"\x00":
            filename += bytes([blob_tree[i]])
            i += 1
        i += 1
        obj_id = blob_tree[i:i+20]
        tree.append([perm, filename, binascii.hexlify(obj_id)])
        i += 20
    return tree

OP_COPY = 1
OP_ADD = 0

def parse_delta(delta_data):
    operations = []
    length = len(delta_data)
    delta_data = io.BytesIO(delta_data)

    while delta_data.tell() < length:
        bitstream = Bitstream(delta_data)
        bits = bitstream.read(8)
        op_type = bits[0]
        meta = bits[1:8]
        print(meta)
        assert(bitstream.buffer == [])
        if op_type == OP_COPY:
            offsets = []
            sizes = []
            copy_start = 0
            metar = list(reversed(meta))
            for i, b in enumerate(metar[:4]):
                if b == 1:
                    sz = delta_data.read(1)[0]
                    copy_start += 256**i * sz
                    offsets.append(sz)
                else:
                    offsets.append(0)
            size = 0
            for i, b in enumerate(metar[4:]):
                if b == 1:
                    sz = delta_data.read(1)[0]
                    size += 256**i * sz
                    sizes.append(sz)
                else:
                    sizes.append(0)
            operations.append(["OP_COPY", meta, offsets, sizes, copy_start, size])
        elif op_type == OP_ADD:
            data_size = bits_to_num(meta)
            append_data = delta_data.read(data_size)
            print(append_data)
            operations.append(["OP_ADD", meta, data_size, append_data])
    return operations

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    options = parser.parse_args()

    with open(options.file, "rb") as packfile:
        res = read_packfile(packfile)
    print(res[0])
    for obj in res[1]:
        print("POS", obj[3])
        print("TYPE:", obj[0])
        print("SIZE:", obj[1])
        if obj[0] == "OBJ_TREE":
            print(parse_tree(obj[2]["compressed"]))
        elif obj[0] == OBJ_REF_DELTA:
            print(obj[2], parse_delta(obj[2]["compressed"]))
        elif obj[0] == OBJ_OFS_DELTA:
            print(obj[2], parse_delta(obj[2]["compressed"]))
        else:
            print("Data:\n", obj[2]["compressed"].decode("latin1"), sep="")
    print("sha", binascii.hexlify(res[2]), binascii.hexlify(res[3]))
if __name__ == "__main__":
    main()
