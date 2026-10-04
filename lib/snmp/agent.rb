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
require 'snmp/agent_mib'
require 'socket'
require 'logger'

module SNMP

  class Agent #:nodoc:all

    DEFAULT_CONTEXT = ""

    attr_reader :vacm
    attr_reader :objects
    attr_reader :local_port

    # Creates an agent.
    #
    # +configure+ takes this agent and should populate the VACM tables and
    # register managed objects.  Without a block a simple default policy is
    # installed: community "public" may read everything and communities
    # "private" may read and write everything.
    def initialize(listen_port=161, max_packet=8000, &configure)
      @log = Logger.new(STDOUT)
      @log.level = Logger::DEBUG
      @max_packet = max_packet
      @listen_port = listen_port
      @socket = nil
      @vacm = VACM.new
      @objects = ObjectStore.new
      if configure
        configure.call(self)
      else
        default_configuration
      end
    end

    # Convenience: register a managed object.
    def register(oid, value)
      @objects.set(oid, value)
    end

    # Community-based requests use the community security model with the
    # community string as the security name; there is no authentication or
    # privacy.
    def security_params(message)
      [VACM::SECURITY_MODEL_V1, message.community.to_s, VACM::NO_AUTH_NO_PRIV, DEFAULT_CONTEXT]
    end

    def default_configuration
      @vacm.add_security_group(VACM::SECURITY_MODEL_V1, "public", "read-only")
      @vacm.add_security_group(VACM::SECURITY_MODEL_V1, "private", "read-write")
      @vacm.add_access("read-only", DEFAULT_CONTEXT, VACM::NO_AUTH_NO_PRIV,
                       read: "internetView", write: nil, notify: "internetView")
      @vacm.add_access("read-write", DEFAULT_CONTEXT, VACM::NO_AUTH_NO_PRIV,
                       read: "internetView", write: "internetView", notify: "internetView")
      @vacm.add_view_family("internetView", "1.3.6.1")
    end

    def start
      @log.info "SNMP agent running"
      bind
      loop do
        begin
          data, remote_info = @socket.recvfrom(@max_packet)
          message = Message.decode(data)
          response_message = handle_message(message)
          encoded_message = response_message.encode
          @socket.send(encoded_message, 0, remote_info[3], remote_info[1])
        rescue => e
          @log.error e
        end
      end
    end

    def bind
      @socket = UDPSocket.open
      @socket.bind(nil, @listen_port)
      @local_port = @socket.addr[1]
    end

    # Decode +data+, service the request and return the encoded response.
    # This is split out from the receive loop so it can be unit tested.
    def process_data(data)
      handle_message(Message.decode(data)).encode
    end

    def handle_message(message)
      model, security_name, level, context = security_params(message)
      pdu = message.pdu
      case pdu
      when GetRequest
        response = message.response
        handle_get(response.pdu, model, security_name, level, context, message.version)
      when GetNextRequest
        response = message.response
        handle_get_next(response.pdu, model, security_name, level, context, message.version)
      when GetBulkRequest
        response = message.response
        handle_get_bulk(response.pdu, pdu, model, security_name, level, context)
      when SetRequest
        response = message.response
        handle_set(response.pdu, model, security_name, level, context, message.version)
      else
        response = message.response
        set_error(response.pdu, :genErr, 1, message.version)
      end
      response
    end

    private

    def handle_get(pdu, model, security_name, level, context, version)
      pdu.varbind_list.each_with_index do |varbind, index|
        decision = @vacm.authorize(model, security_name, level, context,
                                   VACM::READ_VIEW, varbind.name)
        unless decision.allowed?
          return set_error(pdu, denied_status(version), index + 1, version)
        end
        value = @objects.get(varbind.name)
        if value
          varbind.value = value
        elsif version == :SNMPv1
          return set_error(pdu, :noSuchName, index + 1, version)
        else
          varbind.value = NoSuchInstance
        end
      end
    end

    def handle_get_next(pdu, model, security_name, level, context, version)
      pdu.varbind_list.each_with_index do |varbind, index|
        view_name = next_read_view(model, security_name, level, context, varbind.name)
        unless view_name
          return set_error(pdu, denied_status(version), index + 1, version)
        end
        next_oid = @objects.next_oid(varbind.name) do |candidate|
          @vacm.oid_visible?(view_name, candidate)
        end
        if next_oid.nil?
          if version == :SNMPv1
            return set_error(pdu, :noSuchName, index + 1, version)
          end
          varbind.value = EndOfMibView
        else
          varbind.name = ObjectId.new(next_oid)
          varbind.value = @objects.get(next_oid)
        end
      end
    end

    def handle_get_bulk(response_pdu, request_pdu, model, security_name, level, context)
      request_list = request_pdu.varbind_list
      non_repeaters = [request_pdu.non_repeaters, request_list.length].min
      max_repetitions = [request_pdu.max_repetitions, 0].max

      results = VarBindList.new

      # Non-repeaters: answered like GetNext.
      non_repeaters.times do |index|
        varbind = request_list[index].dup
        results << varbind
        fill_next(varbind, model, security_name, level, context)
      end

      # Repeater columns.
      columns = request_list[non_repeaters..-1] || []
      positions = columns.map { |varbind| varbind.name.to_a }
      max_repetitions.times do
        all_end_of_mib = true
        columns.each_with_index do |_, column_index|
          varbind = VarBind.new(ObjectId.new(positions[column_index]), Null)
          fill_next(varbind, model, security_name, level, context)
          results << varbind
          if varbind.value == EndOfMibView
            # Keep repeating from the same OID: fill_next returns
            # endOfMibView again until every column finishes this row.
          else
            all_end_of_mib = false
            positions[column_index] = varbind.name.to_a
          end
        end
        break if all_end_of_mib
      end

      response_pdu.varbind_list = results
    end

    # Fill a single varbind with the next visible object.  Access denials and
    # the end of the MIB both produce endOfMibView for v2c bulk handling.
    def fill_next(varbind, model, security_name, level, context)
      view_name = next_read_view(model, security_name, level, context, varbind.name)
      unless view_name
        varbind.value = EndOfMibView
        return
      end
      next_oid = @objects.next_oid(varbind.name) do |candidate|
        @vacm.oid_visible?(view_name, candidate)
      end
      if next_oid.nil?
        varbind.value = EndOfMibView
      else
        varbind.name = ObjectId.new(next_oid)
        varbind.value = @objects.get(next_oid)
      end
    end

    # Resolve the read view for the request principal (RFC 3415 steps 1-2).
    # Visibility is checked for each candidate object so GETNEXT walks that
    # start at (or inside) an excluded family simply skip it, instead of
    # returning an object and then dropping its varbind.
    def next_read_view(model, security_name, level, context, _requested_oid)
      group = @vacm.group_name(model, security_name)
      return nil unless group
      entry = @vacm.access_entry(group, context, model, level, VACM::READ_VIEW)
      entry && entry.read_view
    end

    def handle_set(pdu, model, security_name, level, context, version)
      pdu.varbind_list.each_with_index do |varbind, index|
        # An unmanaged OID cannot be created by this agent; report it as
        # notWritable (v2c) or noSuchName (v1).
        if @objects.get(varbind.name).nil?
          status = version == :SNMPv1 ? :noSuchName : :notWritable
          return set_error(pdu, status, index + 1, version)
        end
        decision = @vacm.authorize(model, security_name, level, context,
                                   VACM::WRITE_VIEW, varbind.name)
        unless decision.allowed?
          status = version == :SNMPv1 ? :noSuchName : :noAccess
          return set_error(pdu, status, index + 1, version)
        end
      end
      pdu.varbind_list.each { |varbind| @objects.set(varbind.name, varbind.value) }
    end

    # v1 has no noAccess error; RFC 3584 uses noSuchName.
    def denied_status(version)
      version == :SNMPv1 ? :noSuchName : :noAccess
    end

    def set_error(pdu, status, error_index, version)
      status = :noSuchName if version == :SNMPv1 && status == :noAccess
      pdu.error_status = status
      pdu.error_index = error_index
      nil
    end

    def shutdown
      @log.info "SNMP agent stopping"
      @socket.close if @socket && !@socket.closed?
      exit
    end

    alias stop :shutdown

  end

end

if $0 == __FILE__
  agent = SNMP::Agent.new(1061)
  trap("INT") { agent.shutdown }
  agent.start
end
