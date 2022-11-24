import io
import re
import sys
import binascii
from argparse import ArgumentParser
from math import ceil

hexfile = open("arr.bin", 'rb')
hexstr = str(binascii.hexlify(hexfile.read()))
array_name = "data" # The name to give to the generated array.
array_type = "const char" # The data type of the generated array.
array_width = 16 # The number of array elements per row.
byte_length = 1 # The byte length of each array element.
trim_size = None # Trim the input to the specified size.
swap_endianness = False # Swap the byte ordering of the generated array.
body_indent = 4

# opening brace convention - adjust as you please.
if True:
    # data[] = {
    opening_brace = ' = {\n'
else:
    # data[] =
    # {
    opening_brace = ' =\n{\n'

output_code = {
    'header': '%s %s[%d]',
    'rows': [{
        'offset': 0,
        'data': []
    }]
}

class HexStream(object):
    def __init__(self, buf, datasz, swap_bytes):
        self._stream = io.BufferedReader(io.BytesIO(buf), len(buf))
        self._swap = swap_bytes

        self.bufsz = ceil(len(buf) / datasz)
        self.datasz = datasz

    def read(self):
        while len(self._stream.peek()) != 0:
            read_data = self._stream.read(self.datasz)

            if self._swap:
                read_data = read_data[::-1] # python just makes it so easy, lol.

            yield (self._stream.tell() - 1, read_data.hex().zfill(self.datasz * 2))


def main(hex_stream):
    offset_width = 0

    for offset, data in hex_stream.read():
        last_row = output_code['rows'][-1]

        if len(last_row['data']) == owidth:
            output_code['rows'].append({
                'offset': offset - (hex_stream.datasz - 1),
                'data': []
            })

            last_row = output_code['rows'][-1]

        last_row['data'].append(data)

    if hex_stream.bufsz > (2 ** 32):
        offset_width = 16
    else:
        offset_width = 8

    formatted_code = output_code['header'] % (
        array_type,
        array_name,
        hex_stream.bufsz
    )
    formatted_code += opening_brace
    previous_row_len = 0

    for row_idx, row in enumerate(output_code['rows']):
        row_str = ' ' * body_indent

        row_str += ', '.join(['0x' + x for x in row['data']])

        if row_idx == len(output_code['rows']) - 1:
            # i suck at math; sorry if this seems hideous.
            if len(output_code['rows']) > 1:
                row_str += ' ' * (int(previous_row_len - (offset_width + 10)) - len(row_str) + 4)
            else:
                row_str += ' '
        else:
            row_str += ', '

        row_str += '// 0x%s\n' % format(row['offset'], '0%dx' % offset_width)
        previous_row_len = len(row_str)

        formatted_code += row_str

    formatted_code += '};'

    print(formatted_code)


try:
    hexstr = re.sub('[^A-Fa-f0-9]', '', hexstr.replace('0x', ''))
    
    if len(hexstr) % 2 != 0:
        print('Invalid hex string. Input string has an uneven length.')
    
    hexstr = bytes.fromhex(hexstr)

    data_width = max(min(byte_length, 64), 1) # cap at 512 bits or 8 bits(minimum).
    owidth = array_width

    if trim_size is not None:
        if abs(trim_size) != len(hexstr):
            if trim_size >= 0:
                hexstr = hexstr[trim_size:]
                print(hexstr)
                sys.exit()
            else:
                hexstr = hexstr[:trim_size]
        else:
            print('Failed to trim. Trim size exceeded the byte length of the input.')

    if data_width != 1 and data_width % 2 != 0: # byte length MUST BE EVEN!!
        print("Invalid byte length '%d'." % data_width)

    if owidth > len(hexstr):
        owidth = len(hexstr)
except Exception as e:
    if isinstance(e, IndexError):
        print('missing parameters')

    raise e
    print(str(e))
    # usage(1, str(e))

main(HexStream(hexstr, data_width, swap_endianness))
