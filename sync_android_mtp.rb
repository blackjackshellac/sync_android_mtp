#!/usr/bin/env ruby
#
#find_path_by_usbid () {
#	id="$1"
#	lsusboutput="$(lsusb | grep $id | head -n1)"
#	usbbus="${lsusboutput% Device*}"
#	usbbus="${usbbus#Bus }"
#	usbdevice="${lsusboutput%%:*}"
#	usbdevice="${usbdevice#*Device }"
#
#	# Media Transfer Protocol
#	if [ -d "$XDG_RUNTIME_DIR" ]; then
#		runtimedir="$XDG_RUNTIME_DIR"
#	else
#		runtimedir="/run/user/$USER"
#	fi
#	MtpPath="$runtimedir/gvfs/mtp:host=%5Busb%3A${usbbus}%2C${usbdevice}%5D"
#	# Picture Transfer Protocol
#	PtpPath="$runtimedir/gvfs/gphoto2:host=%5Busb%3A${usbbus}%2C${usbdevice}%5D"
#
#	if [ -d "$MtpPath" ]; then
#		echo "$MtpPath"
#	elif [ -d "$PtpPath" ]; then
#		echo "$PtpPath"
#	else
#		echo "Error: File or directory was not found."
#	fi
#}
#
## USB ID for Nexus 4
#id="18d1:4ee[12]"
#path=$(find_path_by_usbid $id)
#

#$ lsusb -d 18d1:
#Bus 002 Device 036: ID 18d1:4ee1 Google Inc. Nexus 4

require 'optparse'
require 'logger'
require 'find'
require 'fileutils'

ME=File.basename($0, ".rb")
MD=File.dirname(File.expand_path($0))

TMP="/var/tmp/#{ME}/#{ENV['USER']}"
DST="#{TMP}/backup"
LOG="#{TMP}/#{ME}.log"

class Logger
	def die(msg)
		$stdout = STDOUT
		self.error(msg)
		exit 1
	end

	def puts(msg)
		self.info(msg)
	end

	def write(msg)
		self.info(msg)
	end
end

def set_logger(stream, level=Logger::INFO)
	log = Logger.new(stream)
	log.level = level
	log.datetime_format = "%Y-%m-%d %H:%M:%S"
	log.formatter = proc do |severity, datetime, progname, msg|
		"#{severity} #{datetime}: #{msg}\n"
	end
	log
end

$log=set_logger(STDERR)

$opts = {
	:uid=>%x/id -u/.strip,
	:vendor => ENV["SYNC_MTP_VENDOR"]||"18d1",
	:product => ENV["SYNC_MTP_PRODUCT"]||"",
	:src => "",
	:dst => ENV["SYNC_MTP_BACKUP"]||DST,
	:dryrun => false,
	:verbose => false,
	:progress => false,
	:from => true,
	:log => nil
}

def getSymbol(string)
	string=string[1..-1] if string[0].eql?(":")
	string.to_sym
end

def run(cmd, err_msg=nil, opts={:trim=>false,:fail=>true})
	err_msg="Command failed to run: #{cmd}"
	out=%x/#{cmd}/
	if $?.exitstatus != 0
		$log.die err_msg if opts[:fail]
		return nil
	end
	return opts[:trim] ? out.strip! : out
end

def get_mtp_directory(uid)
	dev="#{$opts[:vendor]}:#{$opts[:product]}"
	out=run("lsusb -d #{dev}", "Failed to list usb device #{dev}", :trim=>true, :fail=>false)
	return nil if out.nil?

	$log.die "" if out[/Bus\s(\d+)\s/].nil?
	usbbus=$1
	$log.die "" if out[/Device\s(\d+):/].nil?
	usbdevice=$1

	rtdir="/run/user/#{uid}/"
	$log.die "Runtime dir not found #{rtdir}" unless File.directory?(rtdir)

	mtp_dir=File.join(rtdir, "gvfs/mtp:host=%5Busb%3A#{usbbus}%2C#{usbdevice}%5D/Internal storage/")
	$log.warn "mtp dir not mounted #{mtp_dir}" unless File.directory?(mtp_dir)
	return mtp_dir
end

def parse(gopts)
	begin
		mtp_dir=get_mtp_directory($opts[:uid])||"device not detected"
		optparser = OptionParser.new { |opts|
			opts.banner = "#{ME}.rb [options]\n"

			opts.on('-b', '--backup DIR', String, "Backup directory, default #{$opts[:dst]}") { |dst|
				$opts[:dst]=dst
			}

			opts.on('-f', '--from', "From mtp directory to backup (default): #{mtp_dir}") {
				$opts[:from]=true
			}

			opts.on('-t', '--to', "To the mtp directory from backup: #{mtp_dir}") {
				$opts[:from]=false
			}

			opts.on('-n', '--dry-run', "Dry run") {
				$opts[:dryrun]=true
			}

			opts.on('-p', '--progress', "Progress output") {
				$opts[:progress]=true
			}

			opts.on('-V', '--vendor VENDOR', String, "Vendor code default=#{$opts[:vendor]}") { |vendor|
				$opts[:vendor]=vendor
			}

			opts.on('-P', '--product PRODUCT', String, "Product code default=#{$opts[:product]}") { |product|
				v,p = product.split(/:/,2)
				if p.nil?
					$opts[:product]=product
				else
					$opts[:vendor]=v
					$opts[:product]=p
				end
			}

			opts.on('-l', '--list', "List product codes") {
				# lsusb
				# Bus 002 Device 037: ID 18d1:4ee1 Google Inc. Nexus 4
				out=%x/lsusb/.strip
				$stdout.puts "ID VEND:PROD Description"
				out.split(/\r?\n/).each { |line|
					line.strip!
					next if line[/^.*?: (.*)$/].nil?
					$stdout.puts $1
				}
				exit 0
			}

			opts.on('-L', '--log [FILE]', String, "Log to file instead of stdout, default #{$opts[:log]}") { |file|
				$opts[:log]=file||LOG
				$log.info "Logging to #{$opts[:log].inspect}"
			}

			opts.on('-v', '--verbose', "Verbose output") {
				$opts[:verbose]=true
			}

			opts.on('-D', '--debug', "Turn on debugging output") {
				$log.level = Logger::DEBUG
			}

			opts.on('-h', '--help', "Help") {
				$stdout.puts ""
				$stdout.puts opts
				$stdout.puts "\nEnvironment variables:\n"
				$stdout.puts "\tSYNC_MTP_VENDOR  - usb vendor code\n"
				$stdout.puts "\tSYNC_MTP_PRODUCT - usb product code\n"
				$stdout.puts "\tSYNC_MTP_BACKUP  - default backup directory\n"
				exit 0
			}
		}
		optparser.parse!

		src=get_mtp_directory($opts[:uid])
		dst=$opts[:dst]
		if $opts[:from]
			$opts[:src]=src
			$opts[:dst]=dst
		else
			$opts[:src]=dst
			$opts[:dst]=src
		end

		unless $opts[:log].nil?
			$log.debug "Logging file #{$opts[:log]}"
			FileUtils.mkdir_p(File.dirname($opts[:log]))
			# open log to $stdout
			$stdout=File.open($opts[:log], "a")
			# create a logger pointing to stdout
			$log=set_logger($stdout, $log.level)
			$stdout=$log
		end

	rescue OptionParser::InvalidOption => e
		$log.die e.message
	rescue => e
		$log.die e.message
	end

	gopts
end

$opts=parse($opts)

def sync_blocks(fsrc, fdst, fsize, length)
	offset=0
	while true
		length=fsize if fsize < length

		$log.debug "reading #{length} bytes at offset #{offset}: #{fsize} remaining"

		fsrc.seek offset
		fdst.seek offset

		data=fsrc.read length
		fdst.write data

		print "=" if $opts[:progress]

		offset += length
		fsize  -= length
		break if fsize <= 0
	end
	$stdout.puts "" if $opts[:progress]
end

def sync_file(dest, fname)
	fsize=File.lstat(fname).size
	dname=File.join(dest, fname)
	dsize=-1
	dsize=File.lstat(dname).size if File.exists?(dname)
	size_sync=fsize == dsize
	# size is the same, assume files are synced
	return fsize if size_sync
	$stdout.puts "Sync #{fname}:#{fsize} -> #{dname}:#{dsize}" if $opts[:verbose]
	return fsize if $opts[:dryrun]
	File.open(fname, "rb") { |fsrc|
		File.open(dname, "wb") { |fdst|
			sync_blocks(fsrc, fdst, fsize, 1024*1024)
		}
	}
	return fsize
end

def sync_dir(dest, dname)
	toplevel=dname.chomp("/").scan(/\//).length == 0
	ddir=File.join(dest, dname)
	$stdout.puts "Syncing directory #{ddir}" if toplevel && $opts[:verbose]
	return if File.directory?(ddir)
	$stdout.puts "Creating directory #{ddir}" unless toplevel || !$opts[:verbose]

	FileUtils.mkdir_p(ddir)
end

def sync(sdir, ddir)
	total=0
	files=0
	dirs=0
	tstart=Time.new.to_i
	FileUtils.chdir(sdir) {
		$stdout.puts "Source dir = #{sdir}" if $opts[:verbose]
		$stdout.puts "Backup dir = #{ddir}" if $opts[:verbose]
		Find.find(".") { |e|
			# strip off ./
			e=e[2..-1]
			next if e.nil?
			if File.directory?(e)
				dirs+=1
				sync_dir(ddir, e)
			elsif File.file?(e)
				files+=1
				total+=sync_file(ddir, e)
			else
				$log.warn "Skipping file #{e}: #{File.lstat(e).inspect}"
			end
		}
	}
	tend=Time.new.to_i-tstart
	tend+=1 if tend==0
	mb=total/1024/1024
	$stdout.puts "Synced #{files} files and #{dirs} dirs: #{mb} MB in #{tend} secs - #{mb/tend} MB/s"
end

begin
	FileUtils.mkdir_p($opts[:dst])
	sync($opts[:src], $opts[:dst])
rescue Errno::EIO => e
	$log.die "Quitting on IO error: #{e.message}"
rescue Errno::ENOENT => e
	$log.die e.message
rescue Interrupt => e
	$log.die "Interrupted"
rescue => e
	e.backtrace.each { |tr|
		puts tr
	}
	$log.die e.message
end
