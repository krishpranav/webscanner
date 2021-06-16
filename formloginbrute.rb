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

    def brute_by_force(url, dcreds)
        login_agent = Mechanize.new { |agent| agent.user_agent_alias = 'Mac Safari'}
        login_agent.verify_mode = OpenSSL::SSL::VERIFY_NONE
        login_agent.follow_meta_refersh = true
        login_form = login_agent.get(url).from(:name => /login/)

        if not login_form
            $loginboth.info("Login page not found looks like this instance maybe unauthenticated")
            return "<None>", "<None>"
        end
        
        