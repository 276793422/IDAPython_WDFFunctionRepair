# Open file
fileHandler = open(r"C:\Users\Zoo\Desktop\wdffuncenum.h", "r")
# Get list of all lines in file
listOfLines = fileHandler.readlines()
# Close file
fileHandler.close()

bStart = False
print("def GetNameByID(id):")
print("    switcher = {")
for line in listOfLines:
    if len(line) == 0:
        continue
    if line.find("typedef enum _WDFFUNCENUM {") != -1:
        bStart = True
    if line.find("} WDFFUNCENUM;") != -1:
        bStart = False
    if not bStart:
        continue
    if line.find("=") == -1:
        continue
    if not line.startswith("    "):
        continue
    line2 = line.replace(",", "").replace(" ", "").replace("\r", "").replace("\n", "").split("=")
    str_index = line2[1]
    str_name = line2[0]

    if str_name.endswith(("TableIndex")):
        str_name = str_name[:-10]

    # print(line2[1], line2[0])
    print("        " + str_index + ": " + "'" + str_name + "', ")
print("    }")
print("    return switcher.get(id, 'Unknow name')")
