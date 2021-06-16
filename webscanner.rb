# requires
require "csv"
require "net/http"
require "net/http/persistent"
require "net/https"
require "nmap/program"
require "nmap/xml"
require "optparse"
require "ostruct"
require "text-table"
require "uri"
require "thread"
require 'yaml'
require 'logger'
require 'sqlite3'
require 'fileutils'

require File.dirname(File.realpath(__FILE__)) + '/formloginbrute.rb'

VERSION = '1.0'

class String
    def red; colorize(self, "\e[1m\e[31m"); end
    def green; colorize(self, "\e[1m\e[32m"); end
    def bold; colorize(self, "\e[1m"); end
    def colorize(text, color_code)  "#{color_code}#{text}\e[0m" end
end

class MultiDelegaotr
    def initialize(*targets)
        @targets = targets
    end
    
    def self.delegate(*methods)
        methods.each do |m|
            define_method(m) do |*args|
                @targets.map { |t| t.send(m, *args)}
            end
        end
        self
    end

    class <<self
        alias to new
    end
end


class Scanner
    def initialize(paths_filename, nmap_filename, target_file, savedURLs_filename, target_ips_range, scan_port_range, scan_all_ports, brute_force_mode, number_of_threads)
        FileUtils::mkdir_p 'logs'
        webscannerlog = 'logs/webscanner_output_' + Time.now.strftime('%Y-%m-%d_%H-%M-%S') + '.log'
        $log_file = File.open(webscannerlog, "a")
        $logboth = Logger.new MultiDelegaotr.delegate(:write, :close).to(STDOUT, $log_file)
        $logfile = Logger.new MultiDelegaotr.delegate(:write, :close).to($log_file)
        $logconsole = Logger.new MultiDelegaotr.delegate(:write, :close).to(STDOUT)
        @outdb = 'logs/webscanner_output_' + Time.now.strftime('%Y-%m-%d_%H-%M-%S') + '.db'

        # path filename
        @paths_filename = paths_filename

        # nmap xml file
        @nmap_filename  = nmap_filename

        # input file for host
        @target_file    = target_file

        # file with exploitable url saved from last webscanner run
        @savedURLs_filename = savedURLs_filename

        @target_ips_range = target_ips_range

        @scan_port_range = scan_port_range

        @scan_all_ports = scan_all_ports


        @brute_force_mode = brute_force_mode.downcase

        @thread_count = number_of_threads

        @info = [
            ["App Name", "Url to Application", "Potential Exploit", "Username", "Password"]
        ]


        begin
            @webscanner = SQLite3::Database.new @outdb
            @yasuodb.execute "CREATE TABLE IF NOT EXISTS VulnApps(AppName STRING, AppURL STRING, Exploit STRING, Username STRING, Password STRING)"
        rescue SQLite3::Exception => e
            puts "Exception occured"
            puts e
        end
    end

    