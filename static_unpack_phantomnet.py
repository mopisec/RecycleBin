# static_unpack_phantomnet.py
# Python script that unpacks PhantomNet backdoor statically from the loader binary.
# Author: Naoki Takayama
# License: The MIT License

import hashlib
import pefile
import zlib

# Change filename in this line (if needed)
pe = pefile.PE('e9cb02690d987de8d392d0e24b3ccbb294c751dff73962135913c7ec0d8a8064')

offset = 0
size = 0

for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for entry in rsrc.directory.entries:
        if entry.id == 131:
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            save_as = 'PhantomNet_Backdoor_x86.bin'
        elif entry.id == 132:
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            save_as = 'PhantomNet_Backdoor_x64.bin'

        rsrc_data = pe.get_memory_mapped_image()[offset:offset+size]
        dc_data = zlib.decompress(rsrc_data)

        with open(save_as, 'wb') as payload_file:
            payload_file.write(dc_data)
