# frozen_string_literal: true

require 'snmp/vacm'
require 'minitest/autorun'

class TestVACM < Minitest::Test

  include SNMP

  # View with included and excluded families interleaved.  Subtrees are
  # written out of order on purpose; longest-prefix matching must not depend
  # on insertion order.
  INTERLEAVED_VIEW = {
    '1.3.6.1'              => true,   # whole internet included
    '1.3.6.1.2.1.4'        => false,  # whole ip group excluded
    '1.3.6.1.2.1.4.20'     => true,   # ipAddrTable included again
    '1.3.6.1.2.1.4.20.2'   => false,  # ... except ipAddrEntry-2
    '1.3.6.1.2.1.5'        => true,   # icmp explicitly included
    '1.3.6.1.6'            => false,  # snmpV2 framework excluded
  }

  def build_interleaved
    vacm = VACM.new
    INTERLEAVED_VIEW.each do |subtree, included|
      vacm.add_view_family("mibView", subtree, included: included)
    end
    vacm
  end

  def test_interleaved_family_selection_and_visibility
    vacm = build_interleaved
    checks = {
      '1.3.6.1.2.1.1.1.0'     => ['1.3.6.1',            true],
      '1.3.6.1.2.1.4.1.0'     => ['1.3.6.1.2.1.4',      false],
      '1.3.6.1.2.1.4.20.1.1'  => ['1.3.6.1.2.1.4.20',   true],
      '1.3.6.1.2.1.4.20.2.1'  => ['1.3.6.1.2.1.4.20.2', false],
      '1.3.6.1.2.1.5.1.0'     => ['1.3.6.1.2.1.5',      true],
      '1.3.6.1.6.3.1.1.4.1.0' => ['1.3.6.1.6',          false],
      '1.3.6.2.1'             => [nil,                  false],
    }
    checks.each do |oid, (expected_subtree, expected_visible)|
      entry = vacm.matching_view_entry("mibView", oid)
      actual_subtree = entry && ObjectId.new(entry.subtree).to_str
      puts "oid=#{oid} -> family=#{entry.inspect} visible=#{entry && entry.included?}"
      if expected_subtree.nil?
        assert_nil(actual_subtree, "family for #{oid}")
      else
        assert_equal(expected_subtree, actual_subtree, "family for #{oid}")
      end
      assert_equal(expected_visible, vacm.oid_visible?("mibView", oid), "visibility of #{oid}")
    end
  end

  def test_longest_subtree_beats_shorter_regardless_of_order
    vacm = VACM.new
    vacm.add_view_family("v", "1.3.6.1.2.1.4.20", included: true)
    vacm.add_view_family("v", "1.3.6.1.2.1.4", included: false)
    vacm.add_view_family("v", "1.3.6.1", included: false)
    entry = vacm.matching_view_entry("v", "1.3.6.1.2.1.4.20.1.5")
    assert_equal([1,3,6,1,2,1,4,20], entry.subtree)
    assert entry.included?
  end

  def test_equal_length_subtrees_use_lexicographic_order
    vacm = VACM.new
    vacm.add_view_family("v", "1.3.6.1.2.1.5", included: true)
    vacm.add_view_family("v", "1.3.6.1.2.1.4", included: false)
    # 1.3.6.1.2.1.5 is the largest subtree that matches anything under it
    entry = vacm.matching_view_entry("v", "1.3.6.1.2.1.5.0")
    assert_equal([1,3,6,1,2,1,5], entry.subtree)
    assert entry.included?
  end

  def test_mask_wildcard_bits
    vacm = VACM.new
    # Match 1.3.x.1.2.1 (subidentifier index 2 wildcarded)
    vacm.add_view_family("v", "1.3.6.1.2.1", mask: "110111")
    assert vacm.oid_visible?("v", "1.3.6.1.2.1.4")
    assert vacm.oid_visible?("v", "1.3.9.1.2.1.9")
    refute vacm.oid_visible?("v", "1.3.6.2.2.1.0")
    refute vacm.oid_visible?("v", "1.3.6.1.2")
  end

  def test_raw_binary_mask
    vacm = VACM.new
    vacm.add_view_family("v", "1.3.6.1.2.1.99", mask: "\xA0".b)
    assert_equal "10100000", VACM.format_mask("\xA0".b)
    # Bits 1 and 3 are set, so subidentifier indexes 0 and 2 must match
    # (values 1 and 6); every other position is wildcarded.
    assert vacm.oid_visible?("v", "1.9.6.9.2.1.99.5")
    refute vacm.oid_visible?("v", "2.9.6.9.2.1.99.5")
    refute vacm.oid_visible?("v", "1.9.7.9.2.2.99.5")
  end

  def test_default_mask_matches_full_subtree
    assert VACM.family_match?("1.3.6.1.2.1.1", "1.3.6.1", nil)
    assert VACM.family_match?("1.3.6.1.2.1.1", "1.3.6.1", "")
    refute VACM.family_match?("1.3.6.2", "1.3.6.1", nil)
    refute VACM.family_match?("1.3.6", "1.3.6.1", nil)
  end

  def test_group_lookup_with_any_model_fallback
    vacm = VACM.new
    vacm.add_security_group(VACM::SECURITY_MODEL_V1, "public", "v1group")
    vacm.add_security_group(VACM::SECURITY_MODEL_ANY, "shared", "anygroup")
    assert_equal "v1group", vacm.group_name(VACM::SECURITY_MODEL_V1, "public")
    assert_equal "anygroup", vacm.group_name(VACM::SECURITY_MODEL_USM, "shared")
    assert_nil vacm.group_name(VACM::SECURITY_MODEL_USM, "unknown")
  end

  def test_access_selection_exact_context_beats_prefix
    vacm = VACM.new
    prefix = vacm.add_access("g", "bridge", VACM::NO_AUTH_NO_PRIV,
                             read: "prefixView", context_match: :prefix)
    exact = vacm.add_access("g", "bridge1", VACM::NO_AUTH_NO_PRIV,
                            read: "exactView")
    selected = vacm.access_entry("g", "bridge1", VACM::SECURITY_MODEL_V1,
                                 VACM::NO_AUTH_NO_PRIV, VACM::READ_VIEW)
    puts "access candidates: prefix=(#{prefix}) exact=(#{exact})"
    puts "selected access: #{selected}"
    assert_equal "exactView", selected.read_view
  end

  def test_access_selection_prefix_fallback_and_longest_prefix
    vacm = VACM.new
    short = vacm.add_access("g", "br", VACM::NO_AUTH_NO_PRIV,
                            read: "shortView", context_match: :prefix)
    long = vacm.add_access("g", "bridge", VACM::NO_AUTH_NO_PRIV,
                           read: "longView", context_match: :prefix)
    selected = vacm.access_entry("g", "bridge2", VACM::SECURITY_MODEL_V1,
                                 VACM::NO_AUTH_NO_PRIV, VACM::READ_VIEW)
    puts "prefix candidates: short=(#{short}) long=(#{long})"
    puts "selected access: #{selected}"
    assert_equal "longView", selected.read_view
  end

  def test_access_selection_exact_model_beats_any
    vacm = VACM.new
    vacm.add_access("g", "", VACM::NO_AUTH_NO_PRIV, read: "anyModelView",
                    security_model: VACM::SECURITY_MODEL_ANY)
    vacm.add_access("g", "", VACM::NO_AUTH_NO_PRIV, read: "v1ModelView",
                    security_model: VACM::SECURITY_MODEL_V1)
    selected = vacm.access_entry("g", "", VACM::SECURITY_MODEL_V1,
                                 VACM::NO_AUTH_NO_PRIV, VACM::READ_VIEW)
    puts "selected access: #{selected}"
    assert_equal "v1ModelView", selected.read_view
  end

  def test_access_selection_highest_level_not_above_message
    vacm = VACM.new
    vacm.add_access("g", "", VACM::NO_AUTH_NO_PRIV, read: "noAuthView")
    vacm.add_access("g", "", VACM::AUTH_NO_PRIV, read: "authView")
    vacm.add_access("g", "", VACM::AUTH_PRIV, read: "privView")
    selected = vacm.access_entry("g", "", VACM::SECURITY_MODEL_USM,
                                 VACM::AUTH_NO_PRIV, VACM::READ_VIEW)
    puts "selected access: #{selected}"
    assert_equal "authView", selected.read_view
    assert_nil vacm.access_entry("g", "", VACM::SECURITY_MODEL_USM, 0, VACM::READ_VIEW)
  end

  def test_access_requires_view_for_operation
    vacm = VACM.new
    vacm.add_access("g", "", VACM::NO_AUTH_NO_PRIV, read: "readView")
    assert vacm.access_entry("g", "", 1, 1, VACM::READ_VIEW)
    assert_nil vacm.access_entry("g", "", 1, 1, VACM::WRITE_VIEW)
  end

  def test_authorize_decision_rows
    vacm = build_three_operation_vacm
    allowed = vacm.authorize(1, "operator", VACM::NO_AUTH_NO_PRIV, "",
                             VACM::READ_VIEW, "1.3.6.1.2.1.1.1.0")
    puts "read decision: #{allowed}"
    assert allowed.allowed?
    assert_equal "operators", allowed.group
    assert_equal "readView", allowed.access_entry.read_view
    assert_equal [1,3,6,1,2,1,1], allowed.view_entry.subtree

    denied = vacm.authorize(1, "operator", VACM::NO_AUTH_NO_PRIV, "",
                            VACM::WRITE_VIEW, "1.3.6.1.2.1.4.1.0")
    puts "write decision: #{denied}"
    refute denied.allowed?
    assert_equal :notInView, denied.reason

    assert_nil vacm.authorize(1, "stranger", 1, "", VACM::READ_VIEW, "1.3.6.1").access_entry
    assert_equal :noGroupName,
      vacm.authorize(1, "stranger", 1, "", VACM::READ_VIEW, "1.3.6.1").reason
  end

  def test_read_write_notify_select_different_views
    vacm = build_three_operation_vacm
    oid = "1.3.6.1.6.3.1.1.4.1.0"
    refute vacm.read_allowed?(1, "operator", 1, "", oid)
    refute vacm.write_allowed?(1, "operator", 1, "", "1.3.6.1.2.1.1.1.0")
    assert vacm.notify_allowed?(1, "operator", 1, "", oid)
    notify = vacm.authorize(1, "operator", 1, "", VACM::NOTIFY_VIEW, oid)
    puts "notify decision: #{notify}"
    assert_equal "trapView", notify.access_entry.notify_view
  end

  def build_three_operation_vacm
    vacm = VACM.new
    vacm.add_security_group(1, "operator", "operators")
    vacm.add_access("operators", "", VACM::NO_AUTH_NO_PRIV,
                    read: "readView", write: "writeView", notify: "trapView")
    vacm.add_view_family("readView", "1.3.6.1.2.1.1")
    vacm.add_view_family("writeView", "1.3.6.1.4")
    vacm.add_view_family("trapView", "1.3.6.1.6.3.1.1.4")
    vacm
  end
end
