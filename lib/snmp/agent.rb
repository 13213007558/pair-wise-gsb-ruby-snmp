# frozen_string_literal: true
#
# Copyright (c) 2004-2014 David R. Halliday
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

require 'snmp'
require 'snmp/vacm'
require 'socket'
require 'logger'

module SNMP

  ##
  # A minimal SNMP agent (server) for SNMPv1/SNMPv2c with VACM access
  # control (see SNMP::VACM).
  #
  # Every incoming request is authorized against the configured VACM:
  # the community string becomes the security name, the SNMP version
  # becomes the security model, and the security level is always
  # noAuthNoPriv.  GET and SET check each varbind individually.
  # GETNEXT and GETBULK skip over objects that lie outside the
  # requester's view, so out-of-view objects never appear in a
  # response.
  #
  # Example
  #
  #   agent = SNMP::Agent.new(1061)
  #   agent.mib["1.3.6.1.2.1.1.1.0"] = SNMP::OctetString.new("my agent")
  #   agent.start
  #
  class Agent

    ##
    # Ordered OID/value store backing the agent.  Provides the
    # successor lookup needed to walk the tree for GetNext and GetBulk
    # requests.
    #
    class DataTree
      include Enumerable

      def initialize(values={})
        @oids = []
        @data = {}
        values.each { |oid, value| self[oid] = value }
      end

      def []=(oid, value)
        oid = to_oid(oid)
        if @data.key?(oid)
          @data[oid] = value
        else
          index = @oids.bsearch_index { |entry| entry >= oid } || @oids.length
          @oids.insert(index, oid)
          @data[oid] = value
        end
        value
      end

      def [](oid)
        @data[to_oid(oid)]
      end

      ##
      # The smallest stored OID strictly greater than the given OID, or
      # nil when the given OID is at or beyond the end of the tree.
      #
      def successor(oid)
        oid = to_oid(oid)
        index = @oids.bsearch_index { |entry| entry > oid }
        index && @oids[index]
      end

      def each(&block)
        return enum_for(:each) unless block
        @oids.each { |oid| block.call(oid, @data[oid]) }
      end

      private

      def to_oid(oid)
        oid.is_a?(ObjectId) ? oid : ObjectId.new(oid)
      end
    end

    SECURITY_MODEL_BY_VERSION = {
      SNMPv1: VACM::SECURITY_MODELS[:snmpv1],
      SNMPv2c: VACM::SECURITY_MODELS[:snmpv2c]
    }.freeze

    attr_reader :vacm, :mib

    ##
    # Create an agent.  When listen_port is nil no socket is opened,
    # which is useful for driving handle_message directly (e.g. in
    # tests).  mib defaults to an empty DataTree and vacm defaults to
    # a read-only "public" community with a view of the whole tree.
    #
    def initialize(listen_port=nil, max_packet=8000, mib: nil, vacm: nil,
                   logger: nil)
      @log = logger || default_logger
      @max_packet = max_packet
      @socket = nil
      if listen_port
        @socket = UDPSocket.open
        @socket.bind(nil, listen_port)
      end
      @mib = mib || DataTree.new
      @vacm = vacm || self.class.default_vacm
    end

    ##
    # The default VACM configuration: community "public" (any security
    # model) may read and receive notifications for the entire tree.
    #
    def self.default_vacm
      vacm = VACM.new
      vacm.add_security_to_group(security_model: :any,
                                 security_name: "public",
                                 group_name: "public-ro")
      vacm.add_access(group_name: "public-ro",
                      security_model: :any,
                      read_view: "all",
                      notify_view: "all")
      vacm.add_view_subtree("all", "1")
      vacm
    end

    def start
      raise "no listen socket; pass listen_port to Agent.new" unless @socket
      @log.info "SNMP agent running"
      loop do
        begin
          data, remote_info = @socket.recvfrom(@max_packet)
          message = Message.decode(data)
          response = handle_message(message)
          @socket.send(response.encode, 0, remote_info[3], remote_info[1])
        rescue => e
          @log.error e
        end
      end
    end

    ##
    # Process one decoded request message and return the response
    # message.  All VACM enforcement happens here.
    #
    def handle_message(message)
      response = message.response
      security = security_parameters(message)
      case message.pdu
      when GetRequest
        process_get(message, response, security)
      when GetNextRequest
        process_getnext(message, response, security)
      when GetBulkRequest
        process_getbulk(message, response, security)
      when SetRequest
        process_set(message, response, security)
      else
        raise "invalid message #{message}"
      end
      response
    end

    def shutdown
      @log.info "SNMP agent stopping"
      @socket.close if @socket
      exit
    end

    alias stop shutdown

    private

    def default_logger
      log = Logger.new(STDOUT)
      log.level = Logger::DEBUG
      log
    end

    def security_parameters(message)
      {
        security_model: SECURITY_MODEL_BY_VERSION.fetch(message.version),
        security_name: message.community,
        security_level: :noAuthNoPriv,
        context_name: ""
      }
    end

    ##
    # Run the VACM check and log the selected group/access/view rows
    # so the decision can be audited.
    #
    def check_access(security, operation, oid)
      decision = @vacm.decide(operation: operation, oid: oid, **security)
      @log.debug { decision.to_s }
      decision
    end

    def process_get(message, response, security)
      response.pdu.varbind_list.each_with_index do |varbind, index|
        decision = check_access(security, :read, varbind.name)
        value = decision.allowed? ? @mib[varbind.name] : nil
        if value
          varbind.value = value
        elsif message.version == :SNMPv1
          return error_response(response, :noSuchName, index + 1)
        else
          varbind.value = NoSuchObject
        end
      end
      response
    end

    def process_getnext(message, response, security)
      response.pdu.varbind_list.each_with_index do |varbind, index|
        next_oid = next_accessible_oid(security, varbind.name)
        if next_oid
          varbind.name = next_oid
          varbind.value = @mib[next_oid]
        elsif message.version == :SNMPv1
          return error_response(response, :noSuchName, index + 1)
        else
          varbind.value = EndOfMibView
        end
      end
      response
    end

    def process_getbulk(message, response, security)
      pdu = message.pdu
      non_repeaters = [pdu.non_repeaters, 0].max
      max_repetitions = [pdu.max_repetitions, 0].max
      result = VarBindList.new
      pdu.varbind_list.each_with_index do |varbind, index|
        if index < non_repeaters
          append_next(result, varbind.name, security)
        else
          current = varbind.name
          max_repetitions.times do
            next_oid = next_accessible_oid(security, current)
            if next_oid
              result << VarBind.new(next_oid, @mib[next_oid])
              current = next_oid
            else
              result << VarBind.new(current.to_oid, EndOfMibView)
              break
            end
          end
        end
      end
      response.pdu.varbind_list = result
      response
    end

    def process_set(message, response, security)
      response.pdu.varbind_list.each_with_index do |varbind, index|
        decision = check_access(security, :write, varbind.name)
        next if decision.allowed?
        status = message.version == :SNMPv1 ? :noSuchName : :notWritable
        return error_response(response, status, index + 1)
      end
      response.pdu.varbind_list.each do |varbind|
        @mib[varbind.name] = varbind.value
      end
      response
    end

    ##
    # The next OID in the tree that is inside the requester's read
    # view.  Objects outside the view are skipped, never returned and
    # then removed.
    #
    def next_accessible_oid(security, oid)
      while (next_oid = @mib.successor(oid))
        return next_oid if check_access(security, :read, next_oid).allowed?
        oid = next_oid
      end
      nil
    end

    def append_next(result, oid, security)
      next_oid = next_accessible_oid(security, oid)
      if next_oid
        result << VarBind.new(next_oid, @mib[next_oid])
      else
        result << VarBind.new(oid.to_oid, EndOfMibView)
      end
    end

    def error_response(response, status, index)
      response.pdu.error_status = status
      response.pdu.error_index = index
      response
    end

  end

end

if $0 == __FILE__
  agent = SNMP::Agent.new(1061)
  trap("INT") { agent.shutdown }
  agent.start
end
