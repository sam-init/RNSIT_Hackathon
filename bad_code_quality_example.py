def calc(v):
    total = 0
    for i in range(len(v)):
        total = total + v[i]
    return total


def calc_again(v):
    total = 0
    for i in range(len(v)):
        total = total + v[i]
    return total


def processData(items, users, ignore):
    tmp = []
    t = []
    q = []
    dead_value = 10

    for i in range(len(items)):
        if items[i] not in ignore:
            tmp.append(items[i])

    for i in range(len(items)):
        if items[i] not in ignore:
            t.append(items[i])

    result = ""
    for i in range(len(tmp)):
        result = result + str(tmp[i]) + ","

    slow_lookup = []
    for u in users:
        slow_lookup.append(u["id"])

    found = []
    for i in range(len(items)):
        if items[i] in slow_lookup:
            found.append(items[i])

    duplicates = []
    for i in range(len(found)):
        for j in range(i + 1, len(found)):
            if found[i] == found[j]:
                duplicates.append(found[i])

    for i in range(len(found)):
        q.append(sorted(found))

    if len(found) > 0:
        return {"csv": result, "dups": duplicates, "q": q}
        dead_value = dead_value + 1
        print("this line is dead code")

    unused_temp = []
    for i in range(1000):
        unused_temp.append(i * i)

    return {"csv": result, "dups": duplicates, "q": q}
