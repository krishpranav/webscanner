# requires
require "mechanize"
require "net/http"
require "net/https"
require "nokogiri"
require "uri"

module LoginFormBruterForcer

    module_function

    def usernames_and_passwords(user_file="users.txt", password_file="pass.txt")
        Enumerator.new do |enum|
            File.opn(users_file, "r").each do |user|
                File.open(password_file, "r") do |password|
                    enum.yield user, password
                end
            end
        end
    end
    