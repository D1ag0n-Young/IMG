import gdb
 
 
class loadsym(gdb.Command):
    """
    load symbol file to glibc
    Usage: loadsym {symbol file}
    Example:
        (gdb) loadsym '/path/to/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so'
    """
 
    def __init__(self):
        '''
        register command in constructer function
        '''
 
        super(self.__class__, self).__init__("loadsym", gdb.COMMAND_USER)
 
    def invoke(self, args, from_tty):
        '''
        in invoke method, we add command's features
        '''
 
        # using string_to_argv to convert args to list
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise gdb.GdbError(
                'Fail to execute command, use "help loadsym" for help')
        print('[*] symbol file path: {}'.format(argv[0]))
 
        # traverse objfiles to find libc
        for i in gdb.objfiles():
            if 'libc' in i.filename[-12:]:
                self.add_debug_file(i, argv[0])
                return
        print('[-] fail to find libc!')
 
    def add_debug_file(self, objfile, debugfile_path):
        '''
        add debug file and check debug file's status
        '''
 
        objfile.add_separate_debug_file(debugfile_path)
        # check symbol file is loading
        if gdb.lookup_symbol('main_arena') == None:
            print('[-] load debug file fail!')
            return False
        else:
            print('[+] load debug file success!')
            return True
 
if __name__ == "__main__":
    loadsym()
