# encoding: UTF-8

# This file contains data derived from the IANA Time Zone Database
# (https://www.iana.org/time-zones).

module TZInfo
  module Data
    module Definitions
      module UTC
        include TimezoneDefinition
        
        linked_timezone 'UTC', 'Etc/UTC'
      end
    end
  end
end
