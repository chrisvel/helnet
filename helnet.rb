#! /usr/bin/ruby

require 'open3'
require 'byebug'
require 'net/telnet'
require 'ipaddress'

def banner
  <<-EOF

  dP                dP                     dP  #{'v0.2'.bold}
  88                88                     88
  88d888b. .d8888b. 88 88d888b. .d8888b. d8888P
  88'  `88 88ooood8 88 88'  `88 88ooood8   88
  88    88 88.  ... 88 88    88 88.  ...   88
  dP    dP `88888P' dP dP    dP `88888P'   dP

  |-----
  Automated network scanner for vulnerable telnet accounts
  Copyright (c) 2017 Chris Veleris (#{'@chrisvel'.blue.bold})
  |-----

  EOF
end

class String
  def black;          "\e[30m#{self}\e[0m" end
  def red;            "\e[31m#{self}\e[0m" end
  def green;          "\e[32m#{self}\e[0m" end
  def blue;           "\e[34m#{self}\e[0m" end
  def gray;           "\e[37m#{self}\e[0m" end
  def bold;           "\e[1m#{self}\e[22m" end
end

# Scans for vulnerable telnet servers
class Scanner
  USERPASS_FILE = './userpass'
  THREAD_POOL = 10

  def initialize(cidr)
    @cidr = cidr
    @crends = []
    @hosts = []
  end

  # Reads credentials from a text file
  def read_credentials
    File.readlines(USERPASS_FILE).each do |line|
      user, pass = line.split
      pass = "" if pass == '(none)'
      @crends << ["#{user}", pass]
    end
  end

  # Scans hosts
  def scan(host)
    puts "[#{'*'.blue}] Scanning #{host.blue}..."

    # Create a queue of jobs
    jobs = Queue.new

    # Fill it with 60 pairs of credentials
    @crends.each do |crend|
      jobs.push(user: crend[0], pass: crend[1])
    end
    jobs.push(user: "", pass: "")

    # start a worker for each connection
    workers = (THREAD_POOL).times.map do
      Thread.new do
        begin
          while x = jobs.pop(true)
            alive = connect(host, x[:user], x[:pass])
            x[:pass].strip.empty? ? pass = '(blank)' : pass = x[:pass]
            puts "[#{'$'.green.bold}] Default credentials found: #{x[:user]}:#{pass} [ #{'OK'.green.bold} ]" if alive
          end

          alive = connect(host)
          puts "[#{'!'.green.bold}] #{host}: #{x[:user]}:#{x[:pass]}... [ #{'OK'.green.bold} ]" if alive
        rescue ThreadError
        end
      end
    end
    workers.map(&:join)
  rescue Errno::ECONNRESET => e
    puts "[#{'!'.red}] ERROR: Connection reset by peer"
  end

  # Scans CIDR or IP Address for open telnets
  def find_open_telnets
    puts "[#{'*'.blue}] Scanning #{@cidr.blue.bold}"
    Open3.popen3("nmap -v -p23 #{@cidr} -oG - | grep \"Ports: 23\"") do |stdin, stdout, stderr, wth|
      stdout.sync = true
      stdout.each_line do |line|
        data = line.match(/^Host: (\d+\.\d+\.\d+\.\d+).*Ports: (\d+)\/(\w+).*/)
        puts "[#{'+'.blue}] #{data[1].ljust(13)} #{data[3].ljust(13)}"
        if data[3] == 'open'
          @hosts << data[1]
        end
      end
    end
  end

  # Tries to connect to telnet server with given credentials
  def connect(host, user, pass)
    target = Net::Telnet.new("Host" => host, "Timeout" => 5)
    begin
      target.login(user, pass)
      true
    rescue
      false
    end
  end

  # Batch scans hosts
  def scan_hosts
    if @hosts.any?
      puts "[#{'*'.blue}] Starting to scan hosts for vulnerable telnet credentials"
      @hosts.each do |host|
        scan(host)
      end
    else
      puts "[.] Bad luck, no vulnerable hosts found"
    end
  rescue Errno::ECONNREFUSED => e
    puts "[#{'!'.red}] Connection Refused"
  rescue Net::OpenTimeout => e
    puts "[#{'!'.red}] Connection Timeout"
  end
end

# run babe run
cidr = ARGV[0]
puts banner
begin
  IPAddress.parse(cidr)
  scanner = Scanner.new(cidr)
  scanner.read_credentials
  scanner.find_open_telnets
  scanner.scan_hosts
rescue ArgumentError => e
  puts "Invalid arguments: #{e}"
end
