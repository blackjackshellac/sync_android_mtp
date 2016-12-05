
require 'open3'

module Runner

	DEF_OPTS={
		:dryrun=>false,
		:trim => false,
		:fail => true,
		:verbose => false,
		:errmsg => "Command failed to run"
	}

	@@log = Logger.new(STDERR)

	def self.init(opts)
		DEF_OPTS.keys.each { |key|
			next unless opts.key?(key)
			DEF_OPTS[key]=opts[key]
		}
		@@log = opts[:logger] if opts.key?(:logger)
	end

	def self.gov(opts, key)
		return opts.key?(key) ? opts[key] : DEF_OPTS[key]
	end

	def self.run3(cmd, opts={})
		puts "#{Dir.pwd}/ $ #{cmd}"
		unless gov(opts, :dryrun)
			Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
				# or, if you have to do something with the output
				pid = wait_thr.pid
				exit_status = wait_thr.value
				return exit_status if exit_status != 0
				stdout.each { |line|
					$stdout.puts line
					$stdout.flush
				}
			end
		end
		return 0
	end

#	def self.run(cmd, opts={:dryrun=>false})
#		puts "#{Dir.pwd}/ $ #{cmd}"
#		return if dry_run
#		IO.popen(cmd) do |fd|
#			# or, if you have to do something with the output
#			fd.each { |line|
#				$stdout.puts line
#				$stdout.flush
#			}
#		end
#	end

	def self.run(cmd, opts={})
		err_msg=gov(opts, :errmsg)
		return "" if gov(opts, :dryrun)
		@@log.info "run [#{cmd}]" if gov(opts, :verbose)
		out=%x/#{cmd} 2>&1/
		if $?.exitstatus == 0
			puts out if gov(opts, :verbose)
		else
			f=gov(opts, :fail)
			if f == true
				@@log.error out
				@@log.die err_msg
			end
			out=""
		end
		return gov(opts, :trim) ? out.strip! : out
	end

end
