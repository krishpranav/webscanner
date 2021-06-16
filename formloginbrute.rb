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

        username_field = login_form.field_with(name: /user|email|login|REGEMAIL|name/i)
        password_field = login_form.field_with(name: /pass|pwd|REGCODE/i)
        if not username_field
            $logboth.warn("[+] Could not enumerate the username field, moving on you should check it manually")
            puts("[+] Could not enumerate the username field, moving on you should check it manually").red
            username = "<Check Manually>"
            password = "<Check Manually>"
            return username, password
        end

        username = dcreds.split(':')[0].chomp
        password = dcreds.split(':')[1].chomp
        username_field.value = username
        password_field.value = password

        begin
            $logfile.info("trying app-specific default creds first -> #{dcreds}")
            puts("[+] trying app-specific default creds first -> #{dcreds}\n").green

            login_request = login_form.submit

            sleep 0.5

            if (!login_request.form_with(:name => 'login') and
                login_request.body.scan(/"#{username_field.name}"/i).empty? and
                login_request.body.scan(/"#{username_field.name}"/i).empty?)
              puts "[+] webscammer, found default login credentials for #{url} - #{username}:#{password}\n".green
              $logfile.info("[+] webscanner, found default login credentials for #{url} - #{username} / #{password}")
              return username, password
            end
        