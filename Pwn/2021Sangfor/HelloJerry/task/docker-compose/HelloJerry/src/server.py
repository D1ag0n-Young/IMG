import os, string, random, hashlib
from signal import alarm

SIZE_MAX = 0x8000

dic = string.ascii_letters + string.digits

def proof_of_work():
    random.seed(os.urandom(8))
    proof = ''.join([random.choice(dic) for _ in range(20)])
    digest = hashlib.sha256(proof).hexdigest()
    print("sha256(XXXX+%s) == %s" % (proof[4:],digest))
    print("Give me XXXX:")
    x = raw_input()
    if len(x) != 4 or hashlib.sha256(x + proof[4:]).hexdigest() != digest: 
        return False
    return True

def genrandstr(len):
    result = ""
    for _ in range(len):
        result += random.choice(dic)
    return result
   
def main():
    alarm(60)
    if not proof_of_work():
        return
    alarm(30)
    try:
        code = """
        """

        new = ""
        finished = False

        while SIZE_MAX > len(code):
            new = raw_input("code> ")
            if "EOF" in new:
                finished = True
                break
            code += new + "\n"

        if not finished:
            print("file too large!")
            return

        tmp_filename = "/tmp/" + genrandstr(10)
        run_cmd = "/home/ctf/jerry " + tmp_filename
        clean_cmd = "rm -rf " + tmp_filename

        with open(tmp_filename, "w+") as f:
            f.write(code.encode())

        os.system(run_cmd)
        os.system(clean_cmd)

    except:
        print("Error!")

if __name__ == "__main__":
    main()