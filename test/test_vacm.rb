# frozen_string_literal: true

require 'snmp'
require 'snmp/agent'
require 'minitest/autorun'
require 'logger'

class TestVACM < Minitest::Test

  include SNMP

  SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
  SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
  SYS_UP_TIME  = "1.3.6.1.2.1.1.3.0"
  SYS_CONTACT  = "1.3.6.1.2.1.1.4.0"
  SYS_NAME     = "1.3.6.1.2.1.1.5.0"
  IF_NUMBER    = "1.3.6.1.2.1.2.1.0"
  IF_INDEX_1   = "1.3.6.1.2.1.2.2.1.1.1"
  IF_INDEX_2   = "1.3.6.1.2.1.2.2.1.1.2"
  IF_DESCR_1   = "1.3.6.1.2.1.2.2.1.2.1"
  IF_DESCR_2   = "1.3.6.1.2.1.2.2.1.2.2"

  AGENT_DATA = {
    SYS_DESCR     => SNMP::OctetString.new("test agent"),
    SYS_OBJECT_ID => SNMP::ObjectId.new("1.3.6.1.4.1.9.1.1"),
    SYS_UP_TIME   => SNMP::TimeTicks.new(12345),
    SYS_CONTACT   => SNMP::OctetString.new("noc@example.com"),
    SYS_NAME      => SNMP::OctetString.new("router-1"),
    IF_NUMBER     => SNMP::Integer32.new(2),
    IF_INDEX_1    => SNMP::Integer32.new(1),
    IF_INDEX_2    => SNMP::Integer32.new(2),
    IF_DESCR_1    => SNMP::OctetString.new("eth0"),
    IF_DESCR_2    => SNMP::OctetString.new("eth1")
  }.freeze

  def build_vacm
    vacm = SNMP::VACM.new
    vacm.add_context("vlan1")

    vacm.add_security_to_group(security_model: :snmpv2c,
                               security_name: "public", group_name: "ro")
    vacm.add_security_to_group(security_model: :snmpv1,
                               security_name: "public", group_name: "ro")
    vacm.add_security_to_group(security_model: :snmpv2c,
                               security_name: "private", group_name: "rw")

    # noAuthNoPriv messages get the interleaved view; authNoPriv
    # messages from the same group get the full view instead.
    vacm.add_access(group_name: "ro", security_model: :snmpv2c,
                    security_level: :noAuthNoPriv, read_view: "interleaved")
    vacm.add_access(group_name: "ro", security_model: :snmpv2c,
                    security_level: :authNoPriv, read_view: "all")
    vacm.add_access(group_name: "ro", security_model: :snmpv1,
                    read_view: "interleaved")
    # prefix context match: "vlan1" matches context_prefix "vlan"
    vacm.add_access(group_name: "ro", security_model: :snmpv2c,
                    context_prefix: "vlan", context_match: :prefix,
                    read_view: "all")
    vacm.add_access(group_name: "rw", security_model: :snmpv2c,
                    read_view: "all", write_view: "all")

    # Interleaved included/excluded rows: the longest matching subtree
    # decides, so sysDescr.0 stays visible while the rest of the
    # sysDescr subtree and the ifDescr column are hidden.
    vacm.add_view_subtree("interleaved", "1.3.6.1.2.1.1")
    vacm.add_view_subtree("interleaved", "1.3.6.1.2.1.1.1", type: :excluded)
    vacm.add_view_subtree("interleaved", "1.3.6.1.2.1.1.1.0")
    vacm.add_view_subtree("interleaved", "1.3.6.1.2.1.2.2.1")
    vacm.add_view_subtree("interleaved", "1.3.6.1.2.1.2.2.1.2", type: :excluded)

    # Mask wildcarding the interface index of ifIndex (last bit = 0).
    vacm.add_view_subtree("masked", "1.3.6.1.2.1.2.2.1.1.1", mask: "\xFF\xC0")

    vacm.add_view_subtree("all", "1.3.6.1.2.1")
    vacm
  end

  def build_agent
    logger = Logger.new(IO::NULL)
    SNMP::Agent.new(mib: SNMP::Agent::DataTree.new(AGENT_DATA),
                    vacm: build_vacm, logger: logger)
  end

  def request_message(version, community, pdu)
    SNMP::Message.new(version, community, pdu)
  end

  def get(agent, oids, community: "public", version: :SNMPv2c)
    pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new(oids))
    agent.handle_message(request_message(version, community, pdu))
  end

  def getnext(agent, oid, community: "public", version: :SNMPv2c)
    pdu = SNMP::GetNextRequest.new(1, SNMP::VarBindList.new([oid]))
    agent.handle_message(request_message(version, community, pdu))
  end

  ## -- access entry and view selection -----------------------------

  def test_decision_exposes_selected_group_access_and_view
    vacm = build_vacm
    decision = vacm.decide(operation: :read, oid: SYS_NAME,
                           security_model: 2, security_name: "public")
    assert decision.allowed?
    assert_equal :ok, decision.status
    assert_equal "ro", decision.group_name
    assert_equal "interleaved", decision.view_name
    assert_equal "ro", decision.access_entry.group_name
    assert_equal 1, decision.access_entry.security_level
    assert_equal :exact, decision.access_entry.context_match
    assert_includes decision.to_s, "group=ro"
    assert_includes decision.to_s, "view=interleaved"
  end

  def test_security_level_selects_matching_access_entry
    vacm = build_vacm
    decision = vacm.decide(operation: :read, oid: IF_NUMBER,
                           security_model: 2, security_name: "public",
                           security_level: :authNoPriv)
    assert decision.allowed?
    assert_equal "all", decision.view_name
    assert_equal 2, decision.access_entry.security_level
  end

  def test_prefix_context_match_selects_context_specific_entry
    vacm = build_vacm
    decision = vacm.decide(operation: :read, oid: IF_NUMBER,
                           security_model: 2, security_name: "public",
                           context_name: "vlan1")
    assert decision.allowed?
    assert_equal "all", decision.view_name
    assert_equal "vlan", decision.access_entry.context_prefix
    assert_equal :prefix, decision.access_entry.context_match
  end

  def test_unknown_context_is_denied
    vacm = build_vacm
    decision = vacm.decide(operation: :read, oid: SYS_NAME,
                           security_model: 2, security_name: "public",
                           context_name: "unknown")
    refute decision.allowed?
    assert_equal :unknown_context, decision.status
  end

  def test_unknown_security_name_is_denied
    vacm = build_vacm
    decision = vacm.decide(operation: :read, oid: SYS_NAME,
                           security_model: 2, security_name: "nobody")
    refute decision.allowed?
    assert_equal :unknown_security_name, decision.status
    assert_nil decision.access_entry
  end

  def test_missing_operation_view_is_denied
    vacm = build_vacm
    decision = vacm.decide(operation: :write, oid: SYS_NAME,
                           security_model: 2, security_name: "public")
    refute decision.allowed?
    assert_equal :no_view_for_operation, decision.status
    assert_equal "ro", decision.group_name
  end

  def test_oid_outside_view_is_denied_with_selected_view
    vacm = build_vacm
    decision = vacm.decide(operation: :read, oid: IF_NUMBER,
                           security_model: 2, security_name: "public")
    refute decision.allowed?
    assert_equal :not_in_view, decision.status
    assert_equal "interleaved", decision.view_name
  end

  ## -- view tree family with mask -----------------------------------

  def test_interleaved_include_exclude_rows
    vacm = build_vacm
    assert vacm.view_includes?("interleaved", SYS_DESCR), "re-included leaf"
    refute vacm.view_includes?("interleaved", "1.3.6.1.2.1.1.1"), "excluded subtree"
    assert vacm.view_includes?("interleaved", SYS_NAME)
    refute vacm.view_includes?("interleaved", IF_NUMBER), "outside included subtrees"
    assert vacm.view_includes?("interleaved", IF_INDEX_1)
    refute vacm.view_includes?("interleaved", IF_DESCR_1), "excluded column"
    refute vacm.view_includes?("interleaved", IF_DESCR_2), "excluded column"
  end

  def test_view_mask_wildcards_subidentifiers
    vacm = build_vacm
    assert vacm.view_includes?("masked", IF_INDEX_1)
    assert vacm.view_includes?("masked", IF_INDEX_2), "wildcard index bit"
    refute vacm.view_includes?("masked", IF_DESCR_1), "column bit must match"
    refute vacm.view_includes?("masked", SYS_NAME)
  end

  ## -- GET ----------------------------------------------------------

  def test_get_returns_in_view_object
    response = get(build_agent, [SYS_NAME])
    assert_equal :noError, response.pdu.error_status
    assert_equal SNMP::OctetString.new("router-1"),
                 response.pdu.varbind_list.first.value
  end

  def test_get_out_of_view_object_returns_no_such_object
    response = get(build_agent, [IF_NUMBER, IF_DESCR_1])
    values = response.pdu.varbind_list.map(&:value)
    assert_equal [SNMP::NoSuchObject, SNMP::NoSuchObject], values
  end

  def test_get_with_unknown_community_returns_no_such_object
    response = get(build_agent, [SYS_NAME], community: "nobody")
    assert_equal SNMP::NoSuchObject, response.pdu.varbind_list.first.value
  end

  def test_get_v1_out_of_view_raises_no_such_name
    response = get(build_agent, [SYS_NAME, IF_NUMBER], version: :SNMPv1)
    assert_equal :noSuchName, response.pdu.error_status
    assert_equal 2, response.pdu.error_index
  end

  ## -- GETNEXT / GETBULK skip out-of-view objects -------------------

  def test_getnext_skips_excluded_subtree_but_finds_reincluded_leaf
    response = getnext(build_agent, "1.3.6.1.2.1.1")
    varbind = response.pdu.varbind_list.first
    assert_equal SNMP::ObjectId.new(SYS_DESCR), varbind.name
    assert_equal SNMP::OctetString.new("test agent"), varbind.value
  end

  def test_getnext_skips_object_outside_view
    response = getnext(build_agent, SYS_NAME)
    varbind = response.pdu.varbind_list.first
    assert_equal SNMP::ObjectId.new(IF_INDEX_1), varbind.name,
                 "ifNumber.0 is out of view and must be skipped"
    assert_equal SNMP::Integer32.new(1), varbind.value
  end

  def test_getnext_returns_end_of_mib_view_past_last_visible_object
    response = getnext(build_agent, IF_INDEX_2)
    varbind = response.pdu.varbind_list.first
    assert_equal SNMP::EndOfMibView, varbind.value
  end

  def test_getbulk_repeats_over_visible_objects_only
    pdu = SNMP::GetBulkRequest.new(1, SNMP::VarBindList.new([SYS_DESCR]), 0, 4)
    response = build_agent.handle_message(
      request_message(:SNMPv2c, "public", pdu))
    names = response.pdu.varbind_list.map { |vb| vb.name.to_str }
    assert_equal [SYS_OBJECT_ID, SYS_UP_TIME, SYS_CONTACT, SYS_NAME], names
  end

  def test_getbulk_skips_out_of_view_objects_and_terminates
    pdu = SNMP::GetBulkRequest.new(1, SNMP::VarBindList.new([SYS_NAME]), 0, 4)
    response = build_agent.handle_message(
      request_message(:SNMPv2c, "public", pdu))
    varbinds = response.pdu.varbind_list
    assert_equal 3, varbinds.length
    assert_equal SNMP::ObjectId.new(IF_INDEX_1), varbinds[0].name
    assert_equal SNMP::ObjectId.new(IF_INDEX_2), varbinds[1].name
    assert_equal SNMP::EndOfMibView, varbinds[2].value
  end

  def test_getbulk_honors_non_repeaters
    pdu = SNMP::GetBulkRequest.new(
      1, SNMP::VarBindList.new([SYS_CONTACT, SYS_DESCR]), 1, 2)
    response = build_agent.handle_message(
      request_message(:SNMPv2c, "public", pdu))
    names = response.pdu.varbind_list.map { |vb| vb.name.to_str }
    assert_equal [SYS_NAME, SYS_OBJECT_ID, SYS_UP_TIME], names
  end

  ## -- SET ----------------------------------------------------------

  def test_set_with_write_view_commits_value
    agent = build_agent
    varbind = SNMP::VarBind.new(SYS_NAME, SNMP::OctetString.new("router-2"))
    pdu = SNMP::SetRequest.new(1, SNMP::VarBindList.new([varbind]))
    response = agent.handle_message(
      request_message(:SNMPv2c, "private", pdu))
    assert_equal :noError, response.pdu.error_status
    assert_equal SNMP::OctetString.new("router-2"), agent.mib[SYS_NAME]
  end

  def test_set_without_write_view_is_not_writable
    agent = build_agent
    varbind = SNMP::VarBind.new(SYS_NAME, SNMP::OctetString.new("router-2"))
    pdu = SNMP::SetRequest.new(1, SNMP::VarBindList.new([varbind]))
    response = agent.handle_message(
      request_message(:SNMPv2c, "public", pdu))
    assert_equal :notWritable, response.pdu.error_status
    assert_equal 1, response.pdu.error_index
    assert_equal SNMP::OctetString.new("router-1"), agent.mib[SYS_NAME]
  end

end
