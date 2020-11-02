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
require_relative 'lib/assertions'

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

$log=set_logger(STDERR, Logger::INFO)

$opts = {
	:uid=>%x/id -u/.strip,
	:vendor => ENV["SYNC_MTP_VENDOR"]||"",
	:product => ENV["SYNC_MTP_PRODUCT"]||"",
	:serial => nil,
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
	:print => false,
	:config => nil,
	:detect => true,
	:log => nil,
	:logger => $log,
	:delete_skipped_to => false,
	:link => nil,
	:skip_toplevel => %w/Android/,
	:now => Time.now.strftime("%Y%m%d")
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

def parse_lsusb(line)
	h=nil
	# missing product description
	# Bus 003 Device 017: ID 2717:ff40
	m=line.match(/Bus\s(?<bus>[\d]{3})\sDevice\s(?<dev>[\d]{3}):\sID\s(?<vendor>[\w]{4}):(?<product>[\w]{4})\s?(?<desc>.*)?/)
	unless m.nil?
		#$log.debug m.inspect
		h={}
		m.names.each { |key| h[key.to_sym] = m[key] }
	end
	return h
end

def getDeviceFile(dir, name, val=nil)
	filepath = File.join(dir, name)
	if File.exist?(filepath)
		fileval = File.read(filepath).strip
		return fileval if val.nil? || val.eql?(fileval)
	end
	return nil
end

def findDevice(vend, prod, serial)
	s="/sys/bus/usb/devices/usb*/"
	Dir.glob(s).each { |usbdir|
		$log.debug "Searching #{usbdir} for serial: #{vend}:#{prod}:#{serial}"
		Find.find(usbdir) { |dir|
			next unless File.directory?(dir)

			#iManufacturer           1 LGE
			#iProduct                2 Nexus 5X
			#iSerial                 3 01e75e120bd1b627

			next if getDeviceFile(dir, "idProduct", prod).nil?
			next if getDeviceFile(dir, "idVendor",  vend).nil?
			next if getDeviceFile(dir, "serial", serial).nil?

			product=getDeviceFile(dir, "product")
			product.gsub!(/[()]/, "_") unless prod.nil?

			return {
				:dir => dir,
				:idProduct => prod,
				:idVendor  => vend,
				:serial  => serial,
				:manufacturer => getDeviceFile(dir, "manufacturer"),
				:product => product
			}
		}
	}
	return nil
end

def detect(gopts, jcfg)
	return gopts unless gopts[:detect]
	return gopts unless gopts[:vendor].empty?

	$log.info "Detecting usb devices"
	configs=jcfg[:configs]

# $ lsusb
# Bus 003 Device 019: ID 18d1:4ee1 Google Inc. Nexus Device (MTP)

	out=Runner.run("lsusb", { :fail=>true, :strip=>true, :errmsg=>"Failed to list usb devices" } )

	out.split(/\n/).each { |line|
		line.strip!
		#puts line
		#next if line[/Bus\s([\d]{3})\sDevice\s([\d]{3}):\sID\s([\w]{4}):([\w]{4})\s(.*)/].nil?
		h=parse_lsusb(line)
		next if h.nil?
		#iManufacturer           1 LGE
		#iProduct                2 Nexus 5X
		#iSerial                 3 01e75e120bd1b627

		bus=h[:bus]
		dev=h[:dev]
		vend=h[:vendor]
		prod=h[:product]
		desc=h[:desc]||"unknown"
		vend_prod="#{vend}:#{prod}"
		configs.each_pair { |name, cfg|

			Assertions::not_nil?(cfg[:serial])

			v=cfg[:vendor]
			p=cfg[:product]
			if v.eql?(vend_prod) || (v.eql?(vend) && p.eql?(prod))
				hdev = findDevice(vend, prod, cfg[:serial])
				if !hdev.nil? && cfg[:serial].eql?(hdev[:serial])
					$log.info "Detected #{vend}:#{prod}:#{hdev[:serial]} [#{desc}] [#{hdev[:manufacturer]}/#{hdev[:product]}]"
					$log.info hdev[:dir]
					$log.info "Config=#{name}"
					gopts[:manufacturer]=hdev[:manufacturer]
					gopts[:vendor]=vend
					gopts[:product]=prod
					gopts[:iproduct]=hdev[:product]
					gopts[:serial]=hdev[:serial]
					fillConfig(gopts, jcfg, name)
					return gopts
				end
			end
		}
	}
	$log.warn "No known usb devices detected"
	gopts
end

def get_mtp_directory(gopts, jcfg)
	gopts = detect(gopts, jcfg)

	uid=gopts[:uid]
	dev="#{gopts[:vendor]}"
	if gopts[:vendor][/:/].nil?
		dev+=":#{gopts[:product]}" unless gopts[:product].empty?
	end

	out=Runner.run("lsusb -d #{dev}", {:errmsg=>"Failed to list usb device #{dev}", :trim=>true, :fail=>false})
	return nil if out.nil? || out.empty?

	h=parse_lsusb(out)
	$log.die "Failed to parse lsusb -d #{dev} output [#{out}]" if h.nil?
	#usbbus=h[:bus]
	#usbdevice=h[:dev]

	rtdir="/run/user/#{uid}/"
	$log.die "Runtime dir not found #{rtdir}" unless File.directory?(rtdir)
	# /run/user/1201/gvfs/mtp\:host\=LGE_Nexus_5X_01e75e120bd1b627/
	mtp_host="gvfs/mtp:host=%s %s %s" % [ gopts[:manufacturer], gopts[:iproduct], gopts[:serial] ]
	mtp_host.gsub!(/ /, "_")
	#mtp_dir=File.join(rtdir, "gvfs/mtp:host=%5Busb%3A#{h[:bus]}%2C#{h[:dev]}%5D/")
	mtp_dir=File.join(rtdir, mtp_host)

	#gvfs-mount "mtp://[usb:003,003]/"
	#gvfs-mount "mtp://[usb:#{h[:bus]},#{h[:dev]}]/"
	unless File.directory?(mtp_dir)
		$log.info "Mounting mtp dir #{mtp_dir}"
		cmd=%Q[gvfs-mount 'mtp://[usb:#{h[:bus]},#{h[:dev]}]/']
		out=Runner.run(cmd, {:fail=>false})
		puts out unless out.empty?
	end

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

def fillConfig(gopts, jcfg, name)
	name=name.to_sym
	config=jcfg[:configs][name]

	$log.die "Unknown config name #{name}" if config.nil?
	$log.info "Setting config values for #{name}"

	gopts[:config] = config

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
		elsif gopts.key?(key)
			gopts[key]=config[key]
		else
			# Invalid config key if it is not found in gopts (aka $opts)
			$log.die "Unknown config key #{key}" unless gopts.key?(key)
		end
		$log.info "gopts[#{key}]=#{config[key]}"
	}

end

def parseOptions(gopts, jcfg)
	begin
		config_names=jcfg[:configs].keys
		mtp_dir=get_mtp_directory(gopts, jcfg)||"device not detected"
		optparser = OptionParser.new { |opts|
			opts.banner = "#{ME}.rb [options]\n"

			opts.on('-c', '--config NAME', String, "Config name, one of [#{config_names.join(',')}]") { |name|
				fillConfig(gopts, jcfg, name)
			}

			opts.on('-C', '--common', "Common options (-f -p -v -R)") {
				gopts[:from]=true
				gopts[:progress]=true
				gopts[:verbose]=true
				gopts[:run_scripts]=true
			}

			opts.on('--[no-]detect', "Automatic device detection") { |detect|
				gopts[:detect]=detect
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

			opts.on('-x', '--skip-toplevel DIR', Array, "Skip the given top level dirs") { |skip|
				gopts[:skip_toplevel].concat(skip)
				gopts[:skip_toplevel].uniq!
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

			opts.on('--print', "Print specified config (-c) and exit") {
				gopts[:print] = true
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

		if gopts[:print]
			puts JSON.pretty_generate(gopts[:config])
			exit 0
		end
		if gopts[:sync]
			$log.die "Cannot use --to with --sync" unless gopts[:from]
			gopts[:from]=true
			gopts[:record]=true
			gopts[:delete_skipped_to]=true
		end
		src=get_mtp_directory(gopts, jcfg)

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

		unless gopts[:perms].empty?
			perms=gopts[:perms]
			owner=perms[:owner]
			group=perms[:group]
			mode=perms[:mode]
			uid=nil
			gid=nil

			owner,group=owner.split(/\s*:\s*/,2) unless owner.nil?
			uid=Etc.getpwnam(owner).uid unless owner.nil?
			gid=Etc.getgrnam(group).gid unless group.nil?
			mode=Integer(mode, 8) unless mode.nil?

			perms[:owner]=owner
			perms[:group]=group
			perms[:mode]=mode
			perms[:uid]=uid
			perms[:gid]=gid
			gopts[:perms]=perms

		end

		if gopts[:skip_toplevel].empty?
			$re_skip_toplevel=nil
		else
			# RE_ANDROID_TOPLEVEL=/^Android(\/.*|$)/
			dirs=gopts[:skip_toplevel].join("|")
			#rs=%r/(#{x.join("|")})(\/)?(.*)?/
			$re_skip_toplevel=%r/(#{dirs})\/?(.*|$)/
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
$opts= parseOptions($opts, $cfg)

Runner.init($opts)

def sync_blocks(fsrc, fdst, fsize, length, opts)
	offset=0
	while true
		length=fsize if fsize < length

		$log.debug "reading #{length} bytes at offset #{offset}: #{fsize} remaining"

		fsrc.seek offset
		fdst.seek offset

		data=fsrc.read length
		fdst.write data

		print "=" if opts[:progress]

		offset += length
		fsize  -= length
		break if fsize <= 0
	end
	$stdout.puts "" if opts[:progress]
end

def ask_yes_no_all(prompt, opts)
	prompt+= " [y/N/all] $ "
	return true if opts[:yes]
	line=Readline.readline(prompt).strip
	unless line[/all/i].nil?
		opts[:yes]=true
		return true
	end
	return line[/(y|yes)/i].nil? ? false : true
end

def sync_delete(dest, fname, opts)
	dname=File.join(dest, fname)
	found=File.exist?(dname)
	return unless found
	if ask_yes_no_all("Delete #{dname}", opts)
		$log.debug "Deleting destination #{dname}"
		opts={ :verbose => opts[:verbose] }
		FileUtils.rm_f(dname, opts) unless opts[:dryrun]
	end
end

def sync_mtime(dname, fmtime, dmtime, opts)
	return unless opts[:from]
	return if dmtime.eql?(fmtime)
	vputs "Setting mtime = #{fmtime}: #{dname}"
	return if opts[:dryrun]
	FileUtils.touch(dname, :mtime=>fmtime)
end

def sync_owner(dname, dstat, owner, uid, opts)
	return if owner.nil? || owner.empty? || uid.nil?
	return if dstat.uid == uid
	vputs "Setting owner #{owner}: #{dname}"
	#%x/chown #{owner} "#{dname}"/
	#throw "Failed to set owner #{owner}: #{dname}" unless $?.exitstatus == 0
	FileUtils.chown(owner, nil, dname) unless opts[:dryrun]
end

def sync_group(dname, dstat, group, gid, opts)
	return if group.nil? || group.empty? || gid.nil?
	return if dstat.gid == gid
	vputs "Setting group #{group}: #{dname}"
	#%x/chgrp #{group} "#{dname}"/
	#throw "Failed to set group #{group}: #{dname}" unless $?.exitstatus == 0
	FileUtils.chown(nil, group, dname) unless opts[:dryrun]
end

def sync_mode(dname, dstat, mode, opts)
	return if mode.nil?
	return if (dstat.mode & 0777) == mode
	begin
	vputs "Setting mode 0%o: %s" % [ mode, dname ]
	rescue => e
		vputs "#{dname}: #{mode}: #{e}"
		exit 1
	end
	#%x/chmod #{mode} "#{dname}"/
	#throw "Failed to set mode #{mode}: #{dname}" unless $?.exitstatus == 0
	FileUtils.chmod mode, dname unless opts[:dryrun]
end

def sync_perms(dname, dstat, opts)
	return unless opts[:from]
	perms = opts[:perms]||{}
	return if perms.empty?
	sync_owner(dname, dstat, perms[:owner], perms[:uid], opts)
	sync_group(dname, dstat, perms[:group], perms[:gid], opts)
	sync_mode(dname, dstat, perms[:mode], opts)
end

def sync_link(dname, opts)
	return if opts[:link].nil?
	#Sync Music/Cohen,_Leonard/Live_Songs/d1t01-leonard_cohen-minute_prologue.ogg:902272 ->
	#/home/tmp/steeve/nexus_5/backup/Internal storage/Music/Cohen,_Leonard/Live_Songs/d1t01-leonard_cohen-minute_prologue.ogg:-1
	# opts[:dst] = "/home/tmp/steeve/nexus_5/backup/",
	#
	# TODO links = dirname(opts[:dst])/links
	#
	# re=/^#{Regexp.quote(opts[:dst])}[\/]?(.*)/
	#
	opts[:dst_re]=/^#{Regexp.quote(opts[:dst])}[\/]?(.*)/ if opts[:dst_re].nil?
	#
	return if dname[opts[:dst_re]].nil?
	flink = File.join(opts[:link], opts[:now], $1)
	return if File.exists?(flink)
	flink_dir = File.dirname(flink)
	unless opts[:dryrun]
		vputs "Link #{dname} -> #{flink}"
		FileUtils.mkdir_p(flink_dir)
		FileUtils.ln_s(dname, flink)
	end
end

def sync_file(dest, fname, opts)
	fstat=File.lstat(fname)
	fsize=fstat.size
	fmtime=fstat.mtime
	dname=File.join(dest, fname)
	dstat=nil
	dsize=-1
	dmtime=-1
	if File.exists?(dname)
		dstat=File.lstat(dname)
		dsize = dstat.size
		dmtime = dstat.mtime
	end
	dsize=File.exists?(dname) ? File.lstat(dname).size : -1
	# size and date are the same, assume files are synced
	if fsize != dsize || !fmtime.eql?(dmtime)
		vputs "Sync #{fname}:#{fsize} -> #{dname}:#{dsize}"
		begin
			unless opts[:dryrun]
				File.open(fname, "rb") { |fsrc|
					File.open(dname, "wb") { |fdst|
						sync_blocks(fsrc, fdst, fsize, 1024*1024, opts)
					}
				}
			end
			sync_link(dname, opts)
		rescue => e
			$log.error "Failed to sync #{fname} to #{dname}: #{e.message}"
			return 0
		end
	end
	dstat=File.lstat(dname) if dstat.nil?
	sync_perms(dname, dstat, opts)
	sync_mtime(dname, fmtime, dmtime, opts)
	return fsize
end

def sync_dir(dest, dname, opts)
	toplevel=dname.chomp("/").scan(/\//).length == 0
	ddir=File.join(dest, dname)
	$log.info "Syncing to #{ddir}" if toplevel && opts[:verbose]
	return if File.directory?(ddir) || opts[:dryrun]
	$log.info "Creating directory #{ddir}" unless toplevel || !opts[:verbose]
	FileUtils.mkdir_p(ddir)
end

RE_ANDROID_DATA_CACHE=/^Android\/data\/.*?\/cache\//i
RE_THUMBNAILS=/(^|\/).thumbnails\//i
RE_SKIP_ARRAY = [ RE_ANDROID_DATA_CACHE, RE_THUMBNAILS ]
def skip_Android(path, opts)

	# no skips
	return false if $re_skip_toplevel.nil?

	# eg. (Android|Music)\/?(.*|$)
	m=$re_skip_toplevel.match(path)
	return false if m.nil?
	#
	# Android                 - m1,m2 = Android,""
	# Android/                - m1,m2 = Android,""
	# Android/some/other/shit - m1,m2 = Android,some/other/shit
	#
	$log.info "Skipping #{m[1]}: #{path}" if m[2].empty?
	true
end

def skip_path(path, opts)
	skip=false
	# /^Android\/data\/.*\/cache\//i
	RE_SKIP_ARRAY.each { |re|
		m=re.match(path)
		next if m.nil?
		if opts[:verbose]
			if File.directory?(path)
				$log.debug "Skipping directory #{path}: #{re.to_s}"
			else
				$log.debug "Skipping path #{path}: #{re.to_s}"
			end
		end
		skip=true
		break
	}
	return skip
end

def sync_src_dst(sdir, ddir, record=nil, opts)
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
			next if skip_Android(e, opts)
			skip=skip_path(e, opts)
			if File.directory?(e)
				next if skip
				dirs+=1
				sync_dir(ddir, e, opts)
			elsif File.file?(e)
				if skip
					sync_delete(ddir, e, opts) if opts[:delete_skipped_to]
					next
				end
				files += 1
				total += sync_file(ddir, e, opts)
				record[e]=true unless record.nil?
			else
				$log.warn "Skipping file #{e}: #{File.lstat(e).inspect}"
			end
		} unless opts[:dryrun]
	}
	tend=Time.new.to_i-tstart
	tend+=1 if tend==0
	mb=total/1024/1024
	vputs("Synced #{files} files and #{dirs} dirs: #{mb} MB in #{tend} secs - #{mb/tend} MB/s", true)
end

def sync_toplevel(toplevel, opts)
	# toplevel is something like: Internal shared storage/foo
	$log.info "toplevel="+toplevel
	$log.info "src="+opts[:src]
	$log.info "dst="+opts[:dst]

	src=File.join(opts[:src], toplevel)
	dst=File.join(opts[:dst], toplevel)

	$log.info "Backup #{src} to #{dst}"

	record = opts[:sync] ? {} : nil
	FileUtils.mkdir_p(dst)
	sync_src_dst(src, dst, record, opts)
	if opts[:sync]
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
				sync_delete(dst, e, opts)
			}
		}
		src,dst=dst,src
		opts[:delete_skipped_to]=false
		opts[:from]=false
		#sync(src, dst)
	end
end

def glob_toplevel(toplevel, opts)
	dirs=[]
	FileUtils.chdir(File.join(opts[:src], toplevel)) {
		Dir.glob("*") { |dir|
			next unless File.directory?(dir)
			next if skip_Android(dir, opts)
			dir = File.join(toplevel, dir)
			$log.info "Found directory #{dir}"
			dirs << dir
		}
	}
	dirs
end

begin
	$log.die "No dirs found in #{$opts[:src]}" if $opts[:dirs].empty?
	$opts[:dirs].each { |toplevel|
		#sync_toplevel(toplevel, $opts)
		dirs=glob_toplevel(toplevel, $opts)
		dirs.each { |dir|
			# dir like Internal shared storage/Music
			sync_toplevel(dir, $opts)
		}
	}
	if $opts[:run_scripts]
		$log.debug "scripts="+$opts[:scripts].inspect
		$opts[:scripts].each { |script|
			script.gsub!('%DST%', $opts[:dst])
			$opts[:dirs].each { |dir|
				scriptdir=script.gsub(/%SRC%/, dir)
				$log.info "running script with src=#{dir}: #{scriptdir}"
				Runner.run(scriptdir, $opts)
			}
		}
	end
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
