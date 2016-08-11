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
require 'readline'
require 'json'
require 'etc'

require_relative 'lib/runner'

ME=File.basename($0, ".rb")
MD=File.dirname(File.expand_path($0))

TMP="/var/tmp/#{ME}/#{ENV['USER']}"
DST="#{TMP}/backup"
LOG="#{TMP}/#{ME}.log"
CFG=File.join(MD, ME+".json")

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
	:dirs => [],
	:dryrun => false,
	:scripts => [],
	:perms => {},
	:run_scripts => false,
	:verbose => false,
	:progress => false,
	:from => true,
	:sync => false,
	:yes => false,
	:log => nil,
	:delete_skipped_to => false
}

def readConfig
	begin
		return File.read(CFG)
	rescue => e
		$log.error "reading json config: #{CFG} [#{e.message}]"
		return nil
	end
end

def parseConfig(json)
	return { :configs =>[] } if json.nil?
	begin
		return JSON.parse(json, :symbolize_names=>true)
	rescue => e
		$log.die "Failed to parse json config: #{CFG} [#{e.message}]"
	end
end

def vputs(msg, force=false)
	$stdout.puts msg if force || $opts[:verbose]
end

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
	dev="#{$opts[:vendor]}"
	dev+=":#{$opts[:product]}" unless $opts[:product].empty?
	$log.info "lsusb -d #{dev}"
	out=run("lsusb -d #{dev}", "Failed to list usb device #{dev}", :trim=>true, :fail=>false)
	return nil if out.nil?

	$log.die "" if out[/Bus\s(\d+)\s/].nil?
	usbbus=$1
	$log.die "" if out[/Device\s(\d+):/].nil?
	usbdevice=$1

	rtdir="/run/user/#{uid}/"
	$log.die "Runtime dir not found #{rtdir}" unless File.directory?(rtdir)

	mtp_dir=File.join(rtdir, "gvfs/mtp:host=%5Busb%3A#{usbbus}%2C#{usbdevice}%5D/")
	$log.warn "mtp dir not mounted #{mtp_dir}" unless File.directory?(mtp_dir)

	$log.info "mtp_dir="+mtp_dir

	return mtp_dir
end

def get_dirs(src)
	$log.info "Getting dirs in #{src}"
	dirs=[]
	FileUtils.chdir(src) {
		Dir.glob('*') { |dir|
			next unless File.directory?(dir)
			dirs << dir
		}
	}
	$log.info "Dirs="+dirs.join(", ")
	dirs
end

def parse(gopts, jcfg)
	begin
		config_names=jcfg[:configs].keys
		mtp_dir=get_mtp_directory($opts[:uid])||"device not detected"
		optparser = OptionParser.new { |opts|
			opts.banner = "#{ME}.rb [options]\n"

			opts.on('-c', '--config NAME', String, "Config name, one of [#{config_names.join(',')}]") { |name|
				name=name.to_sym
				config=jcfg[:configs][name]
				$log.die "Unknown config name #{name}" if config.nil?
				$log.info "Setting config values for #{name}"
				config.keys.each { |key|
					if key.eql?(:scripts)
						# $opts[scripts]={:woot=>["rsync -av DCIM/ /data/photos/steeve/nexus_5/DCIM/"]}
						# look for scripts for this host
						hostname=%x(hostname -s).strip
						user_hostname="#{Etc.getlogin}@#{hostname}".to_sym
						$log.debug "user@host=#{user_hostname} config=#{config[key].inspect}"
						if config[key].key?(user_hostname)
							$log.debug config[key][user_hostname].inspect
							gopts[:scripts]=config[key][user_hostname]
						end
					else
						$log.die "Unknown config value #{key}" unless gopts.key?(key)
						gopts[key]=config[key]
					end
					$log.info "gopts[#{key}]=#{config[key]}"
				}
			}

			opts.on('-b', '--backup DIR', String, "Backup directory, default #{gopts[:dst]}") { |dst|
				gopts[:dst]=dst
			}

			opts.on('-f', '--from', "From mtp directory to backup (default): #{mtp_dir}") {
				gopts[:from]=true
			}

			opts.on('-t', '--to', "To the mtp directory from backup: #{mtp_dir}") {
				gopts[:from]=false
			}

			opts.on('-s', '--sync', "Sync from android to backup then purge old files from backup") {
				gopts[:sync]=true
				gopts[:delete_skipped_to]=true
			}

			opts.on('-y', '--yes', "Answer yes to prompts") {
				gopts[:yes]=true
			}

			opts.on('-d', '--delete-skip-to', "Delete destination files when copy from src is skipped (only for --from, not --to)") {
				gopts[:delete_skipped_to]=true
			}

			opts.on('-n', '--dry-run', "Dry run") {
				gopts[:dryrun]=true
			}

			opts.on('-p', '--progress', "Progress output") {
				gopts[:progress]=true
			}

			opts.on('-V', '--vendor VENDOR', String, "Vendor code default=#{gopts[:vendor]}") { |vendor|
				gopts[:vendor]=vendor
			}

			opts.on('-P', '--product PRODUCT', String, "Product code default=#{gopts[:product]}") { |product|
				v,p = product.split(/:/,2)
				if p.nil?
					gopts[:product]=product
				else
					gopts[:vendor]=v
					gopts[:product]=p
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

			opts.on('-L', '--log [FILE]', String, "Log to file instead of stdout, default #{gopts[:log]}") { |file|
				gopts[:log]=file||LOG
				$log.info "Logging to #{gopts[:log].inspect}"
			}

			opts.on('-R', '--run-scripts', "Run config scripts after transferring data") {
				gopts[:run_scripts]=true
			}

			opts.on('-v', '--verbose', "Verbose output") {
				gopts[:verbose]=true
			}

			opts.on('-D', '--debug', "Turn on debugging output") {
				$log.level = Logger::DEBUG
			}

			opts.on('-h', '--help', "Help") {
				$stdout.puts ""
				$stdout.puts opts
				$stdout.puts <<HELP

Environment variables:

\tSYNC_MTP_VENDOR  - usb vendor code (#{ENV['SYNC_MTP_VENDOR']||"not set"})
\tSYNC_MTP_PRODUCT - usb product code (#{ENV['SYNC_MTP_PRODUCT']||"not set"})
\tSYNC_MTP_BACKUP  - default backup directory (#{ENV['SYNC_MTP_BACKUP']||"not set"})

HELP
				exit 0
			}
		}
		optparser.parse!

		if gopts[:sync]
			$log.die "Cannot use --to with --sync" unless gopts[:from]
			gopts[:from]=true
			gopts[:record]=true
			gopts[:delete_skipped_to]=true
		end
		src=get_mtp_directory(gopts[:uid])

		$log.die "src directory not found for uid=#{gopts[:uid]}: #{gopts.to_json}" if src.nil?

		dst=gopts[:dst]
		if gopts[:from]
			gopts[:src]=src
			gopts[:dst]=dst
		else # --to aka !gopts[:from]
			$log.error "Resetting --delete_skipped_to=false" if gopts[:delete_skipped_to]
			gopts[:delete_skipped_to]=false

			gopts[:src]=dst
			gopts[:dst]=src

			$log.info "src=#{gopts[:src]} dst=#{gopts[:dst]} src=#{src} dst=#{dst}"
		end

		gopts[:dirs]=get_dirs(gopts[:src])

		unless gopts[:log].nil?
			$log.debug "Logging file #{gopts[:log]}"
			FileUtils.mkdir_p(File.dirname(gopts[:log]))
			# open log to $stdout
			$stdout=File.open(gopts[:log], "a")
			# create a logger pointing to stdout
			$log=set_logger($stdout, $log.level)
			$stdout=$log
		end

		vputs "gopts=#{gopts.inspect}"

	rescue OptionParser::InvalidOption => e
		$log.die "Invalid option: "+e.message
	rescue => e
		e.backtrace.each { |tr|
			puts tr
		}
		$log.die "Exception: "+e.message
	end

	gopts
end

$cfg = parseConfig(readConfig())
$opts=parse($opts, $cfg)

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

def ask_yes_no_all(prompt)
	prompt+= " [y/N/all] $ "
	return true if $opts[:yes]
	line=Readline.readline(prompt).strip
	unless line[/all/i].nil?
		$opts[:yes]=true
		return true
	end
	return line[/(y|yes)/i].nil? ? false : true
end

def sync_delete(dest, fname)
	dname=File.join(dest, fname)
	found=File.exist?(dname)
	return unless found
	if ask_yes_no_all("Delete #{dname}")
		$log.debug "Deleting destination #{dname}"
		opts={ :verbose => $opts[:verbose] }
		FileUtils.rm_f(dname, opts) unless $opts[:dryrun]
	end
end

def sync_mtime(dname, fmtime, dmtime)
	return unless $opts[:from]
	return if dmtime.eql?(fmtime)
	vputs "Setting mtime = #{fmtime}: #{dname}"
	return if $opts[:dryrun]
	FileUtils.touch(dname, :mtime=>fmtime)
end

def sync_owner(dname, owner)
	return if owner.nil? || owner.empty?
	vputs "Setting owner #{owner}: #{dname}"
	%x/chown #{owner} "#{dname}"/
	throw "Failed to set owner #{owner}: #{dname}" unless $?.exitstatus == 0
end

def sync_group(dname, group)
	return if group.nil? || group.empty?
	vputs "Setting group #{group}: #{dname}"
	%x/chgrp #{group} "#{dname}"/
	throw "Failed to set group #{group}: #{dname}" unless $?.exitstatus == 0
end

def sync_mode(dname, mode)
	return if mode.nil? || mode.empty?
	vputs "Setting mode #{mode}: #{dname}"
	%x/chmod #{mode} "#{dname}"/
	throw "Failed to set mode #{mode}: #{dname}" unless $?.exitstatus == 0
end

def sync_perms(dname, perms)
	return if perms.empty?
	sync_owner(dname, perms[:owner]) if perms.key?(:owner)
	sync_group(dname, perms[:group]) if perms.key?(:group)
	sync_mode(dname, perms[:mode]) if perms.key?(:mode)
	
end

def sync_file(dest, fname)
	fstat=File.lstat(fname)
	fsize=fstat.size
	fmtime=fstat.mtime
	dname=File.join(dest, fname)
	dsize=-1
	dmtime=-1
	if File.exists?(dname)
		dsize = File.lstat(dname).size
		dmtime = File.lstat(dname).mtime
	end
	dsize=File.exists?(dname) ? File.lstat(dname).size : -1
	# size and date are the same, assume files are synced
	if fsize != dsize || !fmtime.eql?(dmtime)
		vputs "Sync #{fname}:#{fsize} -> #{dname}:#{dsize}"
		begin
			if !$opts[:dryrun]
				File.open(fname, "rb") { |fsrc|
					File.open(dname, "wb") { |fdst|
						sync_blocks(fsrc, fdst, fsize, 1024*1024)
					}
				}
			end
		rescue => e
			$log.error "Failed to sync #{fname} to #{dname}: #{e.message}"
			return 0
		end
	end
	sync_perms(dname, $opts[:perms])
	sync_mtime(dname, fmtime, dmtime)
	return fsize
end

def sync_dir(dest, dname)
	toplevel=dname.chomp("/").scan(/\//).length == 0
	ddir=File.join(dest, dname)
	$log.info "Syncing to #{ddir}" if toplevel && $opts[:verbose]
	return if File.directory?(ddir) || $opts[:dryrun]
	$log.info "Creating directory #{ddir}" unless toplevel || !$opts[:verbose]
	FileUtils.mkdir_p(ddir)
end

RE_ANDROID_DATA_CACHE=/^Android\/data\/.*?\/cache\//i
RE_THUMBNAILS=/(^|\/).thumbnails\//i
RE_SKIP_ARRAY = [ RE_ANDROID_DATA_CACHE, RE_THUMBNAILS ]
def skip_path(path)
	skip=false
	# /^Android\/data\/.*\/cache\//i
	RE_SKIP_ARRAY.each { |re|
		m=re.match(path)
		next if m.nil?
		$log.debug "Skipping path #{path}: #{re.to_s}" if $opts[:verbose]
		skip=true
		break
	}
	return skip
end

def sync(sdir, ddir, record=nil)
	skip = false
	total=0
	files=0
	dirs=0
	tstart=Time.new.to_i
	FileUtils.chdir(sdir) {
		vputs "Source dir = #{sdir}"
		vputs "Backup dir = #{ddir}"
		Find.find(".") { |e|
			# strip off ./
			e=e[2..-1]
			next if e.nil?
			skip=skip_path(e)
			if File.directory?(e)
				next if skip
				dirs+=1
				sync_dir(ddir, e)
			elsif File.file?(e)
				if skip
					sync_delete(ddir, e) if $opts[:delete_skipped_to]
					next
				end
				files += 1
				total += sync_file(ddir, e)
				record[e]=true unless record.nil?
			else
				$log.warn "Skipping file #{e}: #{File.lstat(e).inspect}"
			end
		} unless $opts[:dryrun]
		if $opts[:run_scripts]
			$opts[:scripts].each { |script|
				Runner.run(script, $opts[:dryrun])
			}
		end
	}
	tend=Time.new.to_i-tstart
	tend+=1 if tend==0
	mb=total/1024/1024
	vputs("Synced #{files} files and #{dirs} dirs: #{mb} MB in #{tend} secs - #{mb/tend} MB/s", true)
end

def sync_toplevel(toplevel)
	$log.info "toplevel="+toplevel
	$log.info "src="+$opts[:src]
	$log.info "dst="+$opts[:dst]
	
	src=File.join($opts[:src], toplevel)
	dst=File.join($opts[:dst], toplevel)

	$log.info "Backup #{src} to #{dst}"

	record = $opts[:sync] ? {} : nil
	FileUtils.mkdir_p(dst)
	sync(src, dst, record)
	if $opts[:sync]
		$log.info "Recorded #{record.size} files in sync from"
		# delete files in dst that were not recorded during first sync
		FileUtils.chdir(dst) {
			vputs "Working dir = #{dst}"
			Find.find(".") { |e|
				# strip off ./
				e=e[2..-1]
				next if e.nil?
				next unless File.file?(e)
				next if record.key?(e)
				vputs("Found file not recorded in src: #{e}",true)
				sync_delete(dst, e)
			}
		}
		src,dst=dst,src
		$opts[:delete_skipped_to]=false
		$opts[:from]=false
		#sync(src, dst)
	end
end

begin
	$log.die "No dirs found in #{$opts[:src]}" if $opts[:dirs].empty?
	$opts[:dirs].each { |toplevel|
		sync_toplevel(toplevel)
	}
rescue Errno::EIO => e
	$log.die "Quitting on IO error: #{e.message}"
rescue Errno::ENOENT => e
	$log.die "Not found: "+e.message
rescue Interrupt => e
	$log.die "Interrupted"
rescue => e
	e.backtrace.each { |tr|
		puts tr
	}
	$log.die "Exception: " + e.message
end

