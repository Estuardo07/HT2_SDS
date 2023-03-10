import pefile

#sample_qwrty_dk2
#sample_vg655_25th.exe
#ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
#ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa hybrid analysis

pe = pefile.PE('MALWR/sample_vg655_25th.exe')

pe.print_info()

print('SECCIONES \t')
for section in pe.sections:
    print(section.name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('LLAMADAS A DLL \t')
    print(entry.dll)
    print('LLAMADAS A FUNCIONES \t')
    for function in entry.imports:
        print('\t', function.name)

print("TimeDateStamp: " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])
print("TimeDateStamp: " + hex(pe.FILE_HEADER.TimeDateStamp))
