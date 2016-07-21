
module Runner

	def self.run(cmd, dry_run=false)
		puts "#{Dir.pwd}/ $ #{cmd}"
		return if dry_run
		IO.popen(cmd) do |fd|
			# or, if you have to do something with the output
			fd.each { |line|
				$stdout.puts line
				$stdout.flush
			}
		end
	end

end 
