#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 13 Dec 07
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-08 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
# 


module EventMachine

  # EM::DeferrableChildProcess is a sugaring of a common use-case
  # involving EM::popen.
  # Call the #open method on EM::DeferrableChildProcess, passing
  # a command-string. #open immediately returns an EM::Deferrable
  # object. It also schedules the forking of a child process, which
  # will execute the command passed to #open.
  # When the forked child terminates, the Deferrable will be signalled
  # and execute its callbacks, passing the data that the child process
  # wrote to stdout.
  #
  class DeferrableChildProcess < EventMachine::Connection
    include EventMachine::Deferrable

    # @private
    def initialize
      super
      @data = []
    end

    # Sugars a common use-case involving forked child processes.
    # #open takes a String argument containing an shell command
    # string (including arguments if desired). #open immediately
    # returns an EventMachine::Deferrable object, without blocking.
    #
    # It also invokes EventMachine#popen to run the passed-in
    # command in a forked child process.
    #
    # When the forked child terminates, the Deferrable that
    # #open calls its callbacks, passing the data returned
    # from the child process.
    #
    def self.open cmd
      EventMachine.popen( cmd, DeferrableChildProcess )
    end

    # @private
    def receive_data data
      @data << data
    end

    # @private
    def unbind
      succeed( @data.join )
    end
  end

  # @private
  class SystemCmd < EventMachine::Connection
    def initialize cb
      @cb = cb
      @output = []
    end
    def receive_data data
      @output << data
    end
    def unbind
      @cb.call @output.join(''), get_status if @cb
    end
  end

  # EM::system is a simple wrapper for EM::popen. It is similar to Kernel::system, but requires a
  # single string argument for the command and performs no shell expansion.
  #
  # The block or proc passed to EM::system is called with two arguments: the output generated by the command,
  # and a Process::Status that contains information about the command's execution.
  #
  #  EM.run{
  #    EM.system('ls'){ |output,status| puts output if status.exitstatus == 0 }
  #  }
  #
  # You can also supply an additional proc to send some data to the process:
  #
  #  EM.run{
  #    EM.system('sh', proc{ |process|
  #      process.send_data("echo hello\n")
  #      process.send_data("exit\n")
  #    }, proc{ |out,status|
  #      puts(out)
  #    })
  #  }
  #
  # Like EventMachine.popen, EventMachine.system currently does not work on windows.
  # It returns the pid of the spawned process.
  def EventMachine::system cmd, *args, &cb
    cb ||= args.pop if args.last.is_a? Proc
    init = args.pop if args.last.is_a? Proc

    # merge remaining arguments into the command
    cmd = [cmd, *args] if args.any?

    EM.get_subprocess_pid(EM.popen(cmd, SystemCmd, cb) do |c|
      init[c] if init
    end.signature)
  end
end
