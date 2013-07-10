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


	def check_stuff(n_offset, l_offset, h_offset, c_offset)

		# Reads Prefetch key from registry and prints its value
		key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session\ Manager\\Memory\ Management\\PrefetchParameters", KEY_READ)
		vkey = key.query_value("EnablePrefetcher").data
		
		print_status("EnablePrefetcher Value: #{vkey}")
                        if vkey == 0
                                print_error("(0) = Disabled (Non-Default).")
                        elsif vkey == 1
                                print_good("(1) = Application lauch prefetching enabled (Non-Default).")
                        elsif vkey == 2
                                print_good("(2) = Boot prefetching enabled (Non-Default).")
                        elsif vkey == 3
                                print_good("(3) = Applaunch and boot enabled (Default Value).")
                        else
                                print_error("Error?")

                        end
	
		print_good("Filename\t\t\t\t\t Hash\t\tLastRunTime\t Run Count\t")
		filename = 0	
		sysroot = client.fs.file.expand_path("%SYSTEMROOT%")
		#print_status("DEBUG: #{sysroot}")
		full_path = sysroot + "\\Prefetch\\"
		#print_status("DEBUG: #{full_path}")
		file_type = "*.pf"
		getfile_prefetch_filenames = client.fs.file.search(full_path,file_type,recurse=false,timeout=-1)
		getfile_prefetch_filenames.each do |file|
			filename = ("#{file['path']}\\#{file['name']}")
			check_offsets(n_offset, h_offset, l_offset, c_offset, filename)	
			#print_status("#{filename}")
		end
			
	end


	def check_offsets(n_offset, h_offset, l_offset, c_offset, filename)

		handle = client.railgun.kernel32.CreateFileA(filename, "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING", "FILE_ATTRIBUTE_NORMAL", 0)
		
		if handle['GetLastError'] != 0
                                print_error("There was error!")
                                return nil
                        else

				# Finding the NAME / WORKS NEEDS CLEANUP
				#print_status("DEBUG Getting Name Handle.")
				client.railgun.kernel32.SetFilePointer(handle['return'], n_offset, 0, 0)
				name = client.railgun.kernel32.ReadFile(handle['return'], 60, 60, 4, nil)
				pname = name['lpBuffer']
				#print_status(pname)


				# Finding the HASH / BROKEN	
				client.railgun.kernel32.SetFilePointer(handle['return'], h_offset, 0, 0)
				hash = client.railgun.kernel32.ReadFile(handle['return'], 4, 4, 4, nil)
				#phash = hash['lpBuffer'].unpack('h*')
				phash = "BROKEN"			

	
				# Finding the LastRun	/ BROKEN
				client.railgun.kernel32.SetFilePointer(handle['return'], l_offset, 0, 0) 
				lrun = 	client.railgun.kernel32.ReadFile(handle['return'], 8, 8, 4, nil)
				#print_error("Last Runtime: #{lrun['lpBuffer']}")
				ptime = "BROKEN"

				# RunCount / WORKS
	
				client.railgun.kernel32.SetFilePointer(handle['return'], c_offset, 0, 0)
				count = client.railgun.kernel32.ReadFile(handle['return'], 4, 4, 4, nil)
				prun = count['lpBuffer'].unpack('C*')
				#print_good("Run Count: %s" % prun)
				print_line("#{pname}\t\t\t#{phash}\t\t#{ptime}\t#{prun[0]}")
				#print_status("DEBUG Closing file handle")
	
		client.railgun.kernel32.CloseHandle(handle['return'])
		end
	end



	def run
		
		print_status("Searching for Prefetch Hive Value")

                if not is_admin?
                        print_error("You don't have enough privileges. Try getsystem.")

                end


		begin
		

		filename = nil

		print_status("Running it...")
		
		sysnfo = client.sys.config.sysinfo['OS']

                if sysnfo =~/(Windows XP|2003)/
                        print_status("Detected Windows XP|2003")
                        n_offset = 0x0010 #16 # Offset for NAME on XP
			h_offset = 0x004C # Offset for HASH on XP
			l_offset = 0x0078 # Offset for LastRun on XP
			c_offset = 0x0090 # Offset for RUN COUNT on XP
                else
                        print_error("Error")
                end
		
		#print_status("DEBUG Name offset: #{n_offset}")
		#print_status("DEBUG Hash offset: #{h_offset}")
		#print_status("DEBUG LastRun offset: #{l_offset}")
		#print_status("DEBUG Count offset: #{c_offset}")
		
		check_stuff(n_offset, h_offset, l_offset, c_offset) # Runs everything
		print_good("All Done..")	




		end
	end
end
