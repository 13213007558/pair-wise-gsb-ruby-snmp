# frozen_string_literal: true
#
# View-based Access Control Model (VACM) per RFC 3415.
#
# Access decisions are made in three steps:
#
# 1. Map (security_model, security_name) to a group using the
#    security-to-group table.
# 2. Pick an access entry for (group, context, security_model, security_level,
#    view_type) from the access table.
# 3. Check the view tree family table of the selected view to decide whether
#    the target OID is visible.

require 'snmp/varbind'

module SNMP
  class VACM

    # Security models (RFC 3411).  SNMPv1 and SNMPv2c use the community
    # model (1).  ANY (0) is used as a wildcard in the access table.
    SECURITY_MODEL_ANY = 0
    SECURITY_MODEL_V1 = 1
    SECURITY_MODEL_V2C = 1
    SECURITY_MODEL_USM = 3

    # Security levels (RFC 3411).
    NO_AUTH_NO_PRIV = 1
    AUTH_NO_PRIV = 2
    AUTH_PRIV = 3

    # Operations select one of the three view families of an access entry.
    READ_VIEW = :read
    WRITE_VIEW = :write
    NOTIFY_VIEW = :notify
    VIEW_TYPES = [READ_VIEW, WRITE_VIEW, NOTIFY_VIEW].freeze

    # ViewTreeFamilyType values.
    INCLUDED = 1
    EXCLUDED = 2

    # Result of a full access check.
    class Decision
      attr_reader :group, :access_entry, :view_entry, :allowed, :reason

      def initialize(allowed, reason, group=nil, access_entry=nil, view_entry=nil)
        @allowed = allowed
        @reason = reason
        @group = group
        @access_entry = access_entry
        @view_entry = view_entry
      end

      def allowed?
        @allowed
      end

      def self.allowed(group, access_entry, view_entry)
        new(true, :allowed, group, access_entry, view_entry)
      end

      def self.denied(reason)
        new(false, reason)
      end

      def to_s
        if @allowed
          "allowed by group=#{@group} " \
            "access=(#{@access_entry}) view_family=(#{@view_entry})"
        else
          "denied: #{@reason}"
        end
      end
    end

    # Entry in vacmAccessTable.  Unused view names are nil.
    AccessEntry = Struct.new(:group, :context_prefix, :context_match, :security_model,
                             :security_level, :read_view, :write_view, :notify_view) do
      VIEW_MEMBER = { READ_VIEW => :read_view, WRITE_VIEW => :write_view, NOTIFY_VIEW => :notify_view }

      def view_name(view_type)
        self[VIEW_MEMBER.fetch(view_type)]
      end

      def to_s
        "group=#{group} contextPrefix=#{context_prefix.inspect} " \
          "contextMatch=#{context_match} securityModel=#{security_model} " \
          "securityLevel=#{security_level} read=#{read_view.inspect} " \
          "write=#{write_view.inspect} notify=#{notify_view.inspect}"
      end
    end

    # Entry in vacmViewTreeFamilyTable.
    ViewEntry = Struct.new(:view_name, :subtree, :mask, :type) do
      def included?
        type == VACM::INCLUDED
      end

      def excluded?
        !included?
      end

      def to_s
        "viewName=#{view_name} subtree=#{ObjectId.new(subtree).to_str} " \
          "mask=#{VACM.format_mask(mask)} type=#{included? ? 'included' : 'excluded'}"
      end
    end

    class << self
      # Render a mask as the dotted bit string used by Net-SNMP config,
      # e.g. "\xA0" (10100000) becomes "10100000".
      def format_mask(mask)
        return "" if mask.nil?
        mask.bytes.map { |byte| format('%08b', byte) }.join(".")
      end

      # True when the OID is in the family defined by subtree+mask.
      #
      # A nil (or empty) mask is equivalent to a mask of all ones whose
      # length equals the subtree length: only the subtree subidentifiers are
      # compared.  Set mask bits require equality of the corresponding
      # subidentifier; zero bits are wildcards.  Mask bits beyond the length
      # of the subtree have no corresponding subidentifier and are ignored.
      def family_match?(oid, subtree, mask)
        oid = ObjectId.new(oid)
        subtree = ObjectId.new(subtree)
        return false if oid.length < subtree.length

        if mask.nil? || mask.empty?
          return oid[0, subtree.length] == subtree.to_a
        end

        subtree.each_index do |i|
          byte_index, bit_offset = i.divmod(8)
          byte = mask.getbyte(byte_index)
          break if byte.nil?
          next if (byte & (0x80 >> bit_offset)).zero?
          return false if oid[i] != subtree[i]
        end
        true
      end
    end

    def initialize
      @groups = []
      @access = []
      @views = []
    end

  
    # ------------------------------------------------------------------
    # vacmSecurityToGroupTable
    # ------------------------------------------------------------------

    # Map a security model and security name (community) to a group name.
    # Per RFC 3415 the model-specific group row is tried first, followed by
    # the row for the wildcard model ANY (0).
    def add_security_group(security_model, security_name, group)
      @groups << [security_model, security_name.to_s, group.to_s]
      nil
    end

    def group_name(security_model, security_name)
      security_name = security_name.to_s
      row = @groups.find { |model, name, _| model == security_model && name == security_name }
      row ||= @groups.find { |model, name, _| model == SECURITY_MODEL_ANY && name == security_name }
      row && row[2]
    end

    # ------------------------------------------------------------------
    # vacmAccessTable
    # ------------------------------------------------------------------

    # Add an access entry.  +context_match+ is :exact (default) or :prefix.
    # Nil view names leave the corresponding view family unconfigured.
    def add_access(group, context, security_level,
                   read: nil, write: nil, notify: nil,
                   context_match: :exact, security_model: SECURITY_MODEL_ANY)
      match = context_match == :prefix ? 2 : 1
      entry = AccessEntry.new(group.to_s, context.to_s, match, security_model,
                             security_level, read, write, notify)
      @access << entry
      entry
    end

    # Select the access entry for a (group, context, model, level, view_type)
    # using the RFC 3415 3.2.2 procedure: context exact beats prefix, model
    # exact beats ANY (0), and the entry with the highest security level that
    # does not exceed the message level wins.
    def access_entry(group, context, security_model, security_level, view_type)
      raise ArgumentError, "invalid view type: #{view_type.inspect}" unless VIEW_TYPES.include?(view_type)
      matching = @access.select do |entry|
        next false unless entry.group == group
        next false unless entry.security_level <= security_level
        next false if entry.security_model != SECURITY_MODEL_ANY && entry.security_model != security_model
        next false if entry.view_name(view_type).nil? || entry.view_name(view_type).empty?
        if entry.context_match == 1
          entry.context_prefix == context
        else
          context.start_with?(entry.context_prefix)
        end
      end

      matching.max_by do |entry|
        # Context match: exact beats prefix, longer match beats shorter.
        # Security model: exact model beats ANY.  Higher allowed level wins.
        exact = entry.context_match == 1
        [
          exact ? 1 : 0,
          exact ? context.length : entry.context_prefix.length,
          entry.security_model == SECURITY_MODEL_ANY ? 0 : 1,
          entry.security_level
        ]
      end
    end

    # ------------------------------------------------------------------
    # vacmViewTreeFamilyTable
    # ------------------------------------------------------------------

    # Add a view family.  +mask+ may be nil (match whole subtree), a string
    # of '0'/'1' bits (e.g. "101"), or a raw binary mask.
    def add_view_family(view_name, subtree, included: true, mask: nil)
      mask = normalize_mask(mask)
      entry = ViewEntry.new(view_name.to_s, ObjectId.new(subtree).to_a, mask,
                            included ? INCLUDED : EXCLUDED)
      @views << entry
      entry
    end

    def view_entries(view_name)
      @views.select { |entry| entry.view_name == view_name }
    end

    # Select the family that governs an OID in a view (RFC 3415 5.2.5):
    # among families whose subtree+mask match, the longest subtree wins;
    # equal-length subtrees are ordered lexicographically, largest first.
    def matching_view_entry(view_name, oid)
      candidates = view_entries(view_name).select do |entry|
        family_match?(oid, entry.subtree, entry.mask)
      end
      candidates.sort do |a, b|
        length_order = b.subtree.length <=> a.subtree.length
        length_order.nonzero? || (ObjectId.new(b.subtree) <=> ObjectId.new(a.subtree)) || 0
      end.first
    end

    # OID is visible when the governing family exists and is an included one.
    def oid_visible?(view_name, oid)
      entry = matching_view_entry(view_name, oid)
      !entry.nil? && entry.included?
    end

    # ------------------------------------------------------------------
    # Combined check
    # ------------------------------------------------------------------

    # Full access check.  Returns a Decision carrying the selected group,
    # access entry and governing view family so callers/tests can verify
    # exactly which configuration rows were used.
    def authorize(security_model, security_name, security_level, context, view_type, oid)
      group = group_name(security_model, security_name)
      return Decision.denied(:noGroupName) unless group

      entry = access_entry(group, context, security_model, security_level, view_type)
      return Decision.denied(:noAccessEntry) unless entry

      view_family = matching_view_entry(entry.view_name(view_type), oid)
      if view_family.nil? || view_family.excluded?
        return Decision.denied(:notInView)
      end
      Decision.allowed(group, entry, view_family)
    end

    def read_allowed?(security_model, security_name, security_level, context, oid)
      authorize(security_model, security_name, security_level, context, READ_VIEW, oid).allowed?
    end

    def write_allowed?(security_model, security_name, security_level, context, oid)
      authorize(security_model, security_name, security_level, context, WRITE_VIEW, oid).allowed?
    end

    def notify_allowed?(security_model, security_name, security_level, context, oid)
      authorize(security_model, security_name, security_level, context, NOTIFY_VIEW, oid).allowed?
    end

    private

    def family_match?(oid, subtree, mask)
      self.class.family_match?(oid, subtree, mask)
    end

    def normalize_mask(mask)
      return nil if mask.nil? || mask == ""
      if bit_string?(mask)
        padded = mask + ('0' * ((8 - mask.length) % 8))
        padded.scan(/.{8}/).map { |octet| octet.to_i(2).chr }.join.b
      else
        mask.to_s.b
      end
    end

    def bit_string?(mask)
      mask.is_a?(::String) && !mask.empty? && mask.chars.all? { |c| c == '0' || c == '1' }
    end
  end
end
