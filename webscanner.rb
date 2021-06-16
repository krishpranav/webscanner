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
    