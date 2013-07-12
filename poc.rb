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
	include Msf::Post::File
	
        def initialize(info={})
                super(update_info(info,
                        'Name'          =>      'ExampleTool',
                        'Description'   =>       %q{ Example Description.},
                        'License'       =>      MSF_LICENSE,
                        'Author'        =>      ['jiuweigui'],
                        'Platform'      =>      ['win'],
                        'SessionType'   =>      ['meterpreter']
                ))

        end


	# Checks if Prefetch registry key exists and what value it has.

	
	def prefetch_key_value()

		reg_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session\ Manager\\Memory\ Management\\PrefetchParameters", KEY_READ)
                key_value = reg_key.query_value("EnablePrefetcher").data

		
		 print_status("EnablePrefetcher Value: #{key_value}")

                        if key_value == 0
                                print_error("(0) = Disabled (Non-Default).")
                        elsif key_value == 1
                                print_good("(1) = Application launch prefetching enabled (Non-Default).")
                        elsif key_value == 2
                                print_good("(2) = Boot prefetching enabled (Non-Default).")
                        elsif key_value == 3
                                print_good("(3) = Applaunch and boot enabled (Default Value).")
                        else
                                print_error("No value.")

                        end

	end

	
	
	def gather_info(name_offset, hash_offset, lastrun_offset, runcount_offset, filename)

		# This function seeks and gathers information from specific offsets.

		h = client.railgun.kernel32.CreateFileA(filename, "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING", "FILE_ATTRIBUTE_NORMAL", 0)

		if h['GetLastError'] != 0

                                print_error("There was error!")
                                return nil
                        else

				handle = h['return']

				# Looks for the FILENAME offset, ON SECOND THOUGHT WILL WORK BETTER ON LOOT

				#client.railgun.kernel32.SetFilePointer(handle, name_offset, 0, nil)
                                #name = client.railgun.kernel32.ReadFile(handle, 60, 60, 4, nil)
                                #x = name['lpBuffer']
				#print_line(x)
				

				# RunCount / WORKS
                                # Finds the run count from the prefetch file    

                                client.railgun.kernel32.SetFilePointer(handle, runcount_offset, 0, nil)
                                count = client.railgun.kernel32.ReadFile(handle, 4, 4, 4, nil)
                                prun = count['lpBuffer'].unpack('L*')


				# Looks for the FILETIME offset / WORKS, sort of at least..
				# Need to find a way to convert FILETIME to LOCAL TIME etc...
				client.railgun.kernel32.SetFilePointer(handle, lastrun_offset, 0, 0)
                                tm1 = client.railgun.kernel32.ReadFile(handle, 8, 8, 4, nil)
                                time1 = tm1['lpBuffer']
				time = time1.unpack('h*')[0].reverse.to_i(16)
				


				print_line("#{prun[0]}\t #{time}\t #{filename[20..-1]}")
				
				client.railgun.kernel32.CloseHandle(handle)
		end

	end



	def run

		print_status("Searching for Prefetch Hive Value.")

		if not is_admin?
			
			print_error("You don't have enough privileges. Try getsystem.")
		end


	begin

		print_status("Running it..")

		sysnfo = client.sys.config.sysinfo['OS']

		# Check to see what Windows Version is running.
		# Needed for offsets.
		
		if sysnfo =~/(Windows XP|2003)/

			print_status("Detected Windows XP/2003")

			name_offset = 0x10 # Offset for EXE name in XP / 2003
			hash_offset = 0x4C # Offset for hash in XP / 2003
			lastrun_offset = 0x78 # Offset for LastRun in XP / 2003
			runcount_offset = 0x90 # Offset for RunCount in XP / 2003
		else
			print_error("No offsets for this Windows version.")

		end



		prefetch_key_value
		


		# FIX: Needs to add a check if the path is found or not
		
		sysroot = client.fs.file.expand_path("%SYSTEMROOT%")
		full_path = sysroot + "\\Prefetch\\"
		file_type = "*.pf"
		
		getfile_prefetch_filenames = client.fs.file.search(full_path,file_type,recurse=false,timeout=-1)
                getfile_prefetch_filenames.each do |file|
                        if file.empty? or file.nil?

				print_error("No files or not enough privileges.")
			else
				filename = File.join(file['path'], file['name'])
				gather_info(name_offset, hash_offset, lastrun_offset, runcount_offset, filename)
			end

		end

	end



		print_good("EVERYTHING DONE")	




	end
end
