# encoding: ascii-8bit
# frozen_string_literal: true

require 'snmp/agent'
require 'minitest/autorun'
require 'socket'

class TestAgent < Minitest::Test

  include SNMP

  SYSTEM_DESCR = "1.3.6.1.2.1.1.1.0"
  IP_FORWARDING = "1.3.6.1.2.1.4.1.0"
  IP_ADDR_INDEX = "1.3.6.1.2.1.4.20.1.1.1"
  IP_ADDR_SECRET = "1.3.6.1.2.1.4.20.2.1.1"
  ICMP_IN_ECHO = "1.3.6.1.2.1.5.1.0"
  TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"

  def build_agent
    Agent.new(0) do |agent|
      vacm = agent.vacm
      vacm.add_security_group(VACM::SECURITY_MODEL_V1, "public", "observers")
      vacm.add_security_group(VACM::SECURITY_MODEL_V1, "private", "operators")
      vacm.add_security_group(VACM::SECURITY_MODEL_V1, "trapsender", "notifiers")
      vacm.add_access("observers", "", VACM::NO_AUTH_NO_PRIV,
                      read: "readView", notify: "readView")
      vacm.add_access("operators", "", VACM::NO_AUTH_NO_PRIV,
                      read: "readView", write: "writeView")
      vacm.add_access("notifiers", "", VACM::NO_AUTH_NO_PRIV,
                      notify: "trapView")

      # Interleaved include/exclude families.
      vacm.add_view_family("readView", "1.3.6.1")
      vacm.add_view_family("readView", "1.3.6.1.2.1.4", included: false)
      vacm.add_view_family("readView", "1.3.6.1.2.1.4.20", included: true)
      vacm.add_view_family("readView", "1.3.6.1.2.1.4.20.2", included: false)
      vacm.add_view_family("writeView", "1.3.6.1.2.1.1.1")
      vacm.add_view_family("trapView", "1.3.6.1.6.3.1.1.4")

      agent.register(SYSTEM_DESCR, OctetString.new("ruby-snmp test agent"))
      agent.register(IP_FORWARDING, Integer.new(1))
      agent.register(IP_ADDR_INDEX, Integer.new(1))
      agent.register(IP_ADDR_SECRET, Integer.new(42))
      agent.register(ICMP_IN_ECHO, Integer.new(7))
    end
  end

  def respond(agent, message)
    Message.decode(agent.process_data(message.encode))
  end

  def request(klass, version, community, ids, *args)
    if klass == GetBulkRequest
      non_repeaters, max_repetitions = args
      Message.new(version, community,
                  klass.new(1, VarBindList.new(ids), non_repeaters, max_repetitions))
    else
      Message.new(version, community, klass.new(1, VarBindList.new(ids), *args))
    end
  end

  def test_get_visible_object
    agent = build_agent
    response = respond(agent, request(GetRequest, :SNMPv2c, "public", [SYSTEM_DESCR]))
    assert_equal(:noError, response.pdu.error_status)
    assert_equal("ruby-snmp test agent", response.pdu.varbind_list[0].value.to_s)
  end

  def test_get_excluded_object_is_no_access
    agent = build_agent
    response = respond(agent, request(GetRequest, :SNMPv2c, "public", [IP_FORWARDING]))
    assert_equal(:noAccess, response.pdu.error_status)
    assert_equal(1, response.pdu.error_index)
  end

  def test_get_excluded_object_is_no_such_name_in_v1
    agent = build_agent
    response = respond(agent, request(GetRequest, :SNMPv1, "public", [IP_FORWARDING]))
    assert_equal(:noSuchName, response.pdu.error_status)
    assert_equal(1, response.pdu.error_index)
  end

  def test_unknown_community_is_denied
    agent = build_agent
    response = respond(agent, request(GetRequest, :SNMPv2c, "nobody", [SYSTEM_DESCR]))
    assert_equal(:noAccess, response.pdu.error_status)
  end

  def test_getnext_skips_whole_excluded_subtree
    agent = build_agent
    # 1.3.6.1.2.1.4.1 is excluded; 1.3.6.1.2.1.4.20.1 is visible, but the
    # query starts above it; the next visible object must be the icmp group.
    message = request(GetNextRequest, :SNMPv2c, "public", ["1.3.6.1.2.1.4.20.1.1.1"])
    response = respond(agent, message)
    varbind = response.pdu.varbind_list[0]
    assert_equal(:noError, response.pdu.error_status)
    assert_equal(ICMP_IN_ECHO, varbind.name.to_str)
  end

  def test_getnext_skips_to_reincluded_subtree
    agent = build_agent
    message = request(GetNextRequest, :SNMPv2c, "public", ["1.3.6.1.2.1.4"])
    response = respond(agent, message)
    varbind = response.pdu.varbind_list[0]
    # 1.3.6.1.2.1.4.1 (excluded) must be skipped; 4.20.1 is re-included.
    assert_equal(IP_ADDR_INDEX, varbind.name.to_str)
    assert_equal(1, varbind.value.to_i)
  end

  def test_getnext_does_not_return_excluded_varbind_then_delete_it
    agent = build_agent
    # Walk the whole MIB; every returned name must itself be in the view.
    names = []
    oid = "1.3.6"
    10.times do
      response = respond(agent, request(GetNextRequest, :SNMPv2c, "public", [oid]))
      varbind = response.pdu.varbind_list[0]
      break if varbind.value == EndOfMibView
      names << varbind.name.to_str
      oid = varbind.name
    end
    puts "getnext walk returned: #{names.inspect}"
    assert_includes(names, SYSTEM_DESCR)
    assert_includes(names, IP_ADDR_INDEX)
    assert_includes(names, ICMP_IN_ECHO)
    refute_includes(names, IP_FORWARDING)
    refute_includes(names, IP_ADDR_SECRET)
  end

  def test_getnext_end_of_mib_v2c
    agent = build_agent
    response = respond(agent, request(GetNextRequest, :SNMPv2c, "public", ["1.3.9"]))
    varbind = response.pdu.varbind_list[0]
    assert_equal(EndOfMibView, varbind.value)
    assert_equal("1.3.9", varbind.name.to_str)
  end

  def test_getnext_end_of_mib_v1_is_no_such_name
    agent = build_agent
    response = respond(agent, request(GetNextRequest, :SNMPv1, "public", ["1.3.9"]))
    assert_equal(:noSuchName, response.pdu.error_status)
    assert_equal(1, response.pdu.error_index)
  end

  def test_getbulk_skips_excluded_objects_and_pads_end_of_mib
    agent = build_agent
    bulk = request(GetBulkRequest, :SNMPv2c, "public",
                   ["1.3.6.1.2.1.4", SYSTEM_DESCR], 0, 3)
    response = respond(agent, bulk)
    list = response.pdu.varbind_list
    names = list.map { |vb| vb.name.to_str }
    values = list.map { |vb| vb.value }
    puts "getbulk names: #{names.inspect}"
    # 2 columns x 3 repetitions = 6 varbinds.
    assert_equal(6, list.length)
    # Column 0 walks visible ip subtree then icmp then endOfMibView,
    # never exposing 4.1.0 or 4.20.2.1.1.
    assert_equal(IP_ADDR_INDEX, names[0])
    assert_equal(ICMP_IN_ECHO, names[2])
    assert_equal(EndOfMibView, values[4])
    # Column 1 starts at sysDescr (1); lexicographically next is the
    # re-included ipAddrTable, then icmp, then endOfMibView.
    assert_equal(IP_ADDR_INDEX, names[1])
    assert_equal(ICMP_IN_ECHO, names[3])
    assert_equal(EndOfMibView, values[5])
    refute_includes(names, IP_FORWARDING)
    refute_includes(names, IP_ADDR_SECRET)
  end

  def test_getbulk_non_repeaters
    agent = build_agent
    bulk = request(GetBulkRequest, :SNMPv2c, "public",
                   [SYSTEM_DESCR, "1.3.6.1.2.1.4"], 1, 1)
    response = respond(agent, bulk)
    list = response.pdu.varbind_list
    assert_equal(2, list.length)
    assert_equal(IP_ADDR_INDEX, list[0].name.to_str)
    assert_equal(IP_ADDR_INDEX, list[1].name.to_str)
  end

  def test_set_allowed_for_write_view
    agent = build_agent
    message = Message.new(:SNMPv2c, "private",
                          SetRequest.new(1, VarBindList.new(
                            [VarBind.new(SYSTEM_DESCR, OctetString.new("new descr"))])))
    response = respond(agent, message)
    assert_equal(:noError, response.pdu.error_status)
    assert_equal("new descr", agent.objects.get(SYSTEM_DESCR).to_s)
  end

  def test_set_denied_by_missing_write_view
    agent = build_agent
    message = Message.new(:SNMPv2c, "public",
                          SetRequest.new(1, VarBindList.new(
                            [VarBind.new(SYSTEM_DESCR, OctetString.new("x"))])))
    response = respond(agent, message)
    assert_equal(:noAccess, response.pdu.error_status)
    assert_equal(1, response.pdu.error_index)
    assert_equal("ruby-snmp test agent", agent.objects.get(SYSTEM_DESCR).to_s)
  end

  def test_set_unknown_oid_is_not_writable
    agent = build_agent
    message = Message.new(:SNMPv2c, "private",
                          SetRequest.new(1, VarBindList.new(
                            [VarBind.new("1.3.6.1.2.1.1.99.0", Integer.new(1))])))
    response = respond(agent, message)
    assert_equal(:notWritable, response.pdu.error_status)
  end

  def test_notify_view_check
    agent = build_agent
    decision = agent.vacm.authorize(VACM::SECURITY_MODEL_V1, "trapsender",
                                     VACM::NO_AUTH_NO_PRIV, "",
                                     VACM::NOTIFY_VIEW, TRAP_OID)
    puts "trap decision: #{decision}"
    assert decision.allowed?
    assert_equal("trapView", decision.access_entry.notify_view)
    refute agent.vacm.notify_allowed?(1, "trapsender", 1, "", IP_FORWARDING)
  end

  def test_udp_roundtrip
    agent = build_agent
    agent.bind
    thread = Thread.new do
      begin
        data, remote_info = agent.instance_variable_get(:@socket).recvfrom(8000)
        response_message = agent.handle_message(Message.decode(data))
        agent.instance_variable_get(:@socket).send(response_message.encode, 0,
                                                   remote_info[3], remote_info[1])
      rescue => e
        flunk "server thread failed: #{e.message}"
      end
    end
    socket = UDPSocket.open
    begin
      message = request(GetRequest, :SNMPv2c, "public", [SYSTEM_DESCR])
      socket.send(message.encode, 0, "127.0.0.1", agent.local_port)
      data, = socket.recvfrom(8000)
      response = Message.decode(data)
      assert_equal("ruby-snmp test agent", response.pdu.varbind_list[0].value.to_s)
    ensure
      socket.close
      thread.join
    end
  end

  def test_default_configuration
    agent = Agent.new(0)
    agent.register(SYSTEM_DESCR, "default agent")
    response = respond(agent, request(GetRequest, :SNMPv2c, "public", [SYSTEM_DESCR]))
    assert_equal("default agent", response.pdu.varbind_list[0].value.to_s)

    # public is read-only
    set = Message.new(:SNMPv2c, "public", SetRequest.new(1, VarBindList.new(
      [VarBind.new(SYSTEM_DESCR, OctetString.new("x"))])))
    assert_equal(:noAccess, respond(agent, set).pdu.error_status)

    # private can write
    set = Message.new(:SNMPv2c, "private", SetRequest.new(1, VarBindList.new(
      [VarBind.new(SYSTEM_DESCR, OctetString.new("changed"))])))
    assert_equal(:noError, respond(agent, set).pdu.error_status)
    assert_equal("changed", agent.objects.get(SYSTEM_DESCR).to_s)
  end
end
