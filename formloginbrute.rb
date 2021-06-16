# requires
require "mechanize"
require "net/http"
require "net/https"
require "nokogiri"
require "uri"


module LoginFormBruteForcer

  module_function

  def usernames_and_passwords(users_file="users.txt", password_file="pass.txt")
    Enumerator.new do |enum|
      File.open(users_file, "r").each do |user|
        File.open(password_file, "r").each do |password|
          enum.yield user, password
        end
      end
    end
  end


  def brute_by_force(url,dcreds)
    login_agent = Mechanize.new { |agent| agent.user_agent_alias = 'Mac Safari' }
    login_agent.verify_mode = OpenSSL::SSL::VERIFY_NONE
    login_agent.follow_meta_refresh = true

    login_form = login_agent.get(url).form(:name => /login/)


    if not login_form
      $logboth.info("Login page not found. Looks like this instance maybe unauthenticated")
      return "<None>", "<None>"
    end

    username_field = login_form.field_with(name: /user|email|login|REGEMAIL|name/i)
    password_field = login_form.field_with(name: /pass|pwd|REGCODE/i)
    if not username_field
      $logboth.warn ("[+] Could not enumerate the username field, moving on. You should check it manually")
      puts ("[+] Could not enumerate the username field, moving on. You should check it manually").red
      username = "<Check Manually>"
      password = "<Check Manually>"
      return username, password
    end

    #Smart brute-force code starts here
    username = dcreds.split(':')[0].chomp
    password = dcreds.split(':')[1].chomp
    username_field.value = username
    password_field.value = password

    begin
      $logfile.info("Trying app-specific default creds first -> #{dcreds}")
      puts ("[+] Trying app-specific default creds first -> #{dcreds}\n").green

      login_request = login_form.submit


      sleep 0.5

      if (!login_request.form_with(:name => 'login') and
          login_request.body.scan(/"#{username_field.name}"/i).empty? and
          login_request.body.scan(/"#{username_field.name}"/i).empty?)
        puts "[+] webscanner, found default login credentials for #{url} - #{username}:#{password}\n".green
        $logfile.info("[+] webscanner, found default login credentials for #{url} - #{username} / #{password}")
        return username, password
      end
    rescue Mechanize::ResponseCodeError => exception
      if (exception.response_code != '200' or
          exception.response_code != '301' or
          exception.response_code != '302')
    
        login_request = exception.page
        $logfile.warn("Invalid credentials or user does not have sufficient privileges")
      else
        $logboth.info("Unknown server error")
      end
    end  

    usernames_and_passwords.each do |user, pass|
      username = user.chomp
      password = pass.chomp

      username_field.value = username
      password_field.value = password

      begin
        $logfile.info("Trying combination --> #{username}/#{password}")

        login_request = login_form.submit

        sleep 0.5


        if (!login_request.form_with(:name => 'login') and
            login_request.body.scan(/"#{username_field.name}"/i).empty? and
            login_request.body.scan(/"#{username_field.name}"/i).empty?)
          puts "[+] webscanner, found default login credentials for #{url} - #{username} / #{password}\n".green
          $logfile.info("[+] webscanner, found default login credentials for #{url} - #{username} / #{password}")
          return username, password
        end
      rescue Mechanize::ResponseCodeError => exception
        if (exception.response_code != '200' or
            exception.response_code != '301' or
            exception.response_code != '302')
          login_request = exception.page
          $logfile.warn("Invalid credentials or user does not have sufficient privileges")
        else
          $logboth.info("Unknown server error")
        end
      end
    end

    $logfile.info("Could not find default credentials, sucks")
    puts "Could not find default login credentials, sucks".red
    return "Not Found", "Not Found"
  end
end