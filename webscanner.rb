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
