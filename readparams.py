

def h2i(hexLines):
    if (hexLines == ''):
        return 0
    return int(hexLines.replace(' ','').replace(':',''), 16)

def splitPoint(hexLines):
    gen=hexLines.replace(' ','').replace(':','')[2:]
    gl=len(gen)
    ind = int(gl/2)
    return (int(gen[:ind],16), int(gen[ind:], 16))

def readParams(file):
    f=open(file,'r')
    lines=f.readlines()
    f.close()
    params = {}
    currentHex=''
    currentParam=''
    ecpoints=["Gener", "pub"]

    for line in lines:
        if line[0].isalpha():
            if (currentHex != '' and currentParam != ''):
                #print("key:",currentParam)
                if not currentParam in ecpoints:
                    params[currentParam]=h2i(currentHex)
                else:
                    params[currentParam]=splitPoint(currentHex)
            currentParam = line.strip().replace(':','')[:5]
            currentHex=''
        else:
            currentHex+=line.strip()
    return params