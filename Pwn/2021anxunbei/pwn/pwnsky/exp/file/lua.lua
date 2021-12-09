function Pwnsky(name)
  local self = {}
  local ServerInit = function()
    self.name = name
    self.account = 0
    self.password = 0
    self.is_login = 0
    self.init = init
    self.print_logo = print_logo
  end
  function self.info()
    print("Server Info:")
    local time = os.date("%c")
    print("Server name: " .. self.name)
    print("Date time: " .. time)
    if self.is_login == 0 then
      print("Account status: Not login")
    else
      print("Account status: Logined")
      print("Account : " .. self.account)
    end
  end
  function self.login()
    print("pwnsky cloud cache login")
    io.write("account:")
    self.account = io.read("*number")
    io.write("password:")
    self.password = io.read("*number")
    self.is_login = login(self.account, self.password)
    if self.is_login == 1 then
      print("login succeeded!")
    else
      print("login failed!")
    end
  end
  function self.run()
    while true do
      io.write("$")
      local ops = io.read("*l")
      if ops == "login" then
        self.login()
      elseif ops == "info" then
        self.info()
      elseif ops == "add" then
        if self.is_login == 1 then
          print("size?")
          size = io.read("*number")
          idx = add_data(size)
          print("Data index: " .. idx)
        else
          print("login first...")
        end
      elseif ops == "del" then
        if self.is_login == 1 then
          print("index?")
          index = io.read("*number")
          delete_data(index)
        else
          print("login first...")
        end
      elseif ops == "get" then
        if self.is_login == 1 then
          print("index?")
          index = io.read("*number")
          get_data(index)
        else
          print("login first...")
        end
      elseif ops == "help" then
        print("commands:")
        print("login")
        print("info")
        print("add")
        print("del")
        print("get")
        print("exit")
      elseif ops == "exit" then
        print("exit")
        break
      end
    end
  end
  ServerInit()
  return self
end
function main()
  alarm(60)
  local pwn = Pwnsky("pwnsky cloud cache 1.0")
  pwn:print_logo()
  pwn:info()
  pwn:init()
  pwn:run()
end
