import argparse

class Header:
    def __init__(self, magic, version, count):
        self.magic = magic
        self.version = version
        self.count = count

def read_packfile(bs):
    magic = bs.read(4)
    assert(magic, b"PACK")
    version_b = bs.read(4)
    version = struct.unpack("I!", version_b)[0]
    count_b = bs.read(4)
    count = struct.unpack("I!", count_b)
    return (magic, version, count)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    options = parser.parse_args()

    with open("packfile") as packfile:
        res = read_packfile(packfile)
    print(res)

main()
