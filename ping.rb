
require 'socket'
require 'ipaddr'

# my god this is awful. i can see why people don't do low level
# networking protocols in ruby. And why the documentation is so
# terrible.
#

def adump(arr, msg) 

  STDOUT.puts ">>> #{msg}"
  i=0
  arr.each_char do |n|
    STDOUT.puts "#{i}=#{n[0]}" #data.length
    i += 1
  end
  STDOUT.puts "======="
end

class AddrInfo

  attr_accessor :ip

  def initialize(inp)
    case inp
    when String
      @ip = IPAddr.new(TCPSocket.getaddress(inp)).to_i
    when Fixnum
      @ip = inp
    else
      raise "AddrInfo does not know how to parse #{inp.class}"
    end
  end

  def encode
    [ Socket::AF_INET, 0, @ip, 0, 0 ].pack("v2N3")
  end

  def self.decode(header)
    data = header.unpack("v2N")

    new data[2]
  end

  def ==(other)
    @ip == other.ip
  end

  def to_s
    a = (@ip >> 24) & 0xff
    b = (@ip >> 16) & 0xff
    c = (@ip >>  8) & 0xff
    d = (@ip      ) & 0xff

    "#{a}.#{b}.#{c}.#{d}"
  end

end

class ICMP

  attr_accessor :type, :checksum

  IPPROTO_ICMP = 1

  def initialize(t)
    @type = t
    @checksum = 0
  end

  def packet(data)
    [
      @type,     # 8
      0,         # 8
      @checksum, # 16
      data
    ].pack("C2na*")
  end

  def compute_checksum!

    data = packet
    ck   = 0

    # pad to 16 bit boundery
    data += "\0" if (data.length & 1) != 0

    # now sum the 16 bit values of the packet
    data.unpack('n*').each { |v| ck += v }

    # and some magic
    ck = (ck >> 16) + (ck & 0xffff)
    ck += ck >> 16
    @checksum = (~ck) & 0xffff
  end
end

class Socket 

  attr_accessor :addr

  def self.open(remote)
    sock = new(Socket::AF_INET, Socket::SOCK_RAW, ICMP::IPPROTO_ICMP)
    sock.addr = remote
    sock
  end

  def send(data)
    #adump data, "sending data"
    #adump @addr.encode, "address"

    super data, 0, @addr.encode
  end

  def recv(size = 10024)
    recvfrom size
  end

end

class Response 
  attr_reader :remote_info, :type, :id, :sequence, :time

  ICMP_ECHOREPLY = 0

  def initialize(socket_data)

    #adump socket_data[0], "receiving data"
    #adump socket_data[1], "receiving address"
    
    packet = extract_packet_from_ip_data(socket_data.shift)

    @remote_info = AddrInfo.decode(socket_data.shift)

    data = packet.unpack("C2n3Ga*")

    @type     = data[0]
    @code     = data[1]
    @id       = data[3]
    @sequence = data[4]
    @time     = data[5]
    @mesg     = data[7]
  end

  def to_s
    "response: type=#{@type}, code=#{@code}, id=#{@id}, sequence=#{@sequence}"
  end

  private 

  def extract_packet_from_ip_data(data)
    ofs = (data[0] & 0x0f) * 4

    data.slice(ofs..-1)
  end

end

class Echo < ICMP

  ICMP_ECHO = 8

  def initialize(seq, id = $$)
    super ICMP_ECHO

    @id = id
    @sequence = seq
  end

  def generate(time = Time.now, length = 56)

    @data = 'E' * length
    @time = time.to_f

    compute_checksum!

    packet
  end

  def to_s
    "echo: type=#{type}, id=#{@id}, sequence=#{@sequence}, checksum=#{checksum}"
  end
    

  def packet
    super [
      @id,       # 16
      @sequence, # 16
      @time,
      @data
    ].pack("n2Ga*")
  end
end


target = 'localhost'
count  = 10

remote_address = AddrInfo.new(target)

puts "ping(#{count}): #{target} -> #{remote_address}"


socket = Socket.open(remote_address)

count.times do |n|

  echo = Echo.new(n, 15025)

  #echo.compute_checksum!

  #puts echo

  socket.send echo.generate

  res = nil

  # slight hack. Response will be the ping we sent
  loop do
    res = Response.new(socket.recv)

    break unless res.type == Echo::ICMP_ECHO
  end

  #puts res

  if res.type != Response::ICMP_ECHOREPLY
    puts "fail(#{n}): not ICMP_ECHOREPLY (#{res.type})"
    next
  end

  if res.sequence != n
    puts "fail(#{n}): not in sequence (#{res.sequence})" 
    next
  end

  if res.remote_info != remote_address
    puts "fail(#{n}): not from target (#{res.remote_info})" 
    next
  end

  puts "ping(#{n}): %0.4fms" % ((Time.now.to_f - res.time) * 1000)

  sleep 1 unless n == count - 1
end










