module Assertions
	def self.not_nil?(param)
		raise "Assertions.not_nil? failed" if param.nil?
	end
end
